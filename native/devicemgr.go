package native

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/WangSirMe/tiktok-android-signer/parseerr"
)

// deviceManager 管理进程级注册设备的完整生命周期(parse 与 register 的合并逻辑):
//
//   - 启动预热:StartDeviceWarmup 后台异步注册,失败退避重试直到成功。
//   - 失效标记:parse 失败(设备被风控/配额耗尽)后按代次标记失效,并尝试触发重注册。
//   - 注册阈值:同一 IP 高频 device_register 会触发 TikTok 风控,因此进程内
//     **1 分钟最多启动一次注册流程**。已有注册在跑时,其它失败请求不报错、
//     也不另起注册 —— 等这次注册跑完后直接取结果;只有处于阈值冷却且没有
//     注册可等时才直接报错,让客户端稍后重试。
//
// 注册产物(device_id / install_id / cookie / seed / device_token)有时效与
// 请求次数限制,所以消费方(parse)持有的是「代次 gen」:失效上报只对当前代次
// 生效,过期上报不会误伤刚发布的新设备。
type deviceManager struct {
	mu        sync.Mutex
	device    *nativeDevice
	gen       uint64        // 每次成功发布 +1,消费方凭 gen 上报失效
	invalid   bool          // 当前设备已被标记失效(parse 失败)
	regCh     chan struct{} // 非 nil = 有注册在跑;注册结束(无论成败)后 close
	regErr    error
	lastRegAt time.Time // 最近一次注册流程的启动时间(频率阈值基准)
}

var devices = &deviceManager{}

const (
	// deviceRegMinInterval:注册频率阈值 —— 1 分钟内最多启动一次注册流程。
	// 同一 IP 反复 device_register 会触发 TikTok 风控,必须限频。
	deviceRegMinInterval = time.Minute
	// 启动预热失败重试退避:下限对齐注册阈值(重试也必须 ≥1 分钟),指数翻倍封顶 5 分钟。
	warmupBackoffMin = time.Minute
	warmupBackoffMax = 5 * time.Minute
)

// StartDeviceWarmup 在服务启动时调用:后台异步注册设备直到成功。
// 不阻塞监听端口。预热完成前到达的 parse:有注册在跑则等它跑完,
// 否则按 acquire 的阈值规则处理。
func StartDeviceWarmup() {
	go devices.warmupLoop()
}

func (m *deviceManager) warmupLoop() {
	backoff := warmupBackoffMin
	for {
		m.mu.Lock()
		if m.device != nil && !m.invalid {
			m.mu.Unlock()
			log.Printf("[device-mgr] 已有可用设备,启动预热退出")
			return
		}
		// 已有注册在跑(可能是 parse 触发的):等它;阈值允许则自己启动。
		ch := m.tryStartRegLocked()
		cooldown := m.cooldownRemainingLocked()
		m.mu.Unlock()

		if ch == nil {
			// 阈值窗口内:等冷却结束后再试(对齐 1 分钟限频)。
			if cooldown <= 0 {
				cooldown = time.Second
			}
			time.Sleep(cooldown)
			continue
		}
		dev, err := m.waitReg(context.Background(), ch)
		if err == nil && dev != nil {
			log.Printf("[device-mgr] 启动预热注册成功 (did=%s)", dev.DeviceID)
			return
		}
		log.Printf("[device-mgr] 启动预热注册失败,%s 后重试", backoff)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > warmupBackoffMax {
			backoff = warmupBackoffMax
		}
	}
}

// acquire 返回当前可用设备与其代次。无可用设备时:已有注册在跑则等它跑完
// 直接取结果(不产生额外注册);阈值允许则触发一次注册并等待完成;处于阈值
// 冷却且无注册可等时直接报错 —— 客户端稍后重试。
func (m *deviceManager) acquire(ctx context.Context) (*nativeDevice, uint64, error) {
	m.mu.Lock()
	if m.device != nil && !m.invalid {
		dev, gen := m.device, m.gen
		m.mu.Unlock()
		return dev, gen, nil
	}
	ch := m.tryStartRegLocked()
	m.mu.Unlock()
	if ch == nil {
		return nil, 0, errRegThrottled()
	}
	return m.waitRegGen(ctx, ch)
}

// invalidateAndRefresh 标记指定代次设备失效,并尝试触发重注册、等待其完成后
// 返回新设备。代次不匹配时设备已被换过,直接返回当前设备。已有注册在跑时
// 等它跑完取结果;阈值冷却且无注册可等时报错。
func (m *deviceManager) invalidateAndRefresh(ctx context.Context, gen uint64) (*nativeDevice, error) {
	m.mu.Lock()
	if m.gen == gen && !m.invalid {
		m.invalid = true
		log.Printf("[device-mgr] 设备 gen=%d 标记失效(parse 失败),尝试触发重注册", gen)
	}
	if m.device != nil && !m.invalid {
		// 代次不匹配:设备已被其它请求换新且可用,直接用。
		dev := m.device
		m.mu.Unlock()
		return dev, nil
	}
	ch := m.tryStartRegLocked()
	m.mu.Unlock()
	if ch == nil {
		return nil, errRegThrottled()
	}
	dev, _, err := m.waitRegGen(ctx, ch)
	return dev, err
}

// errRegThrottled 是阈值冷却中(无注册可等)的统一错误:让客户端稍后重试,
// 而不是立刻再起注册(同一 IP 不能反复注册)。
func errRegThrottled() error {
	return parseerr.UpstreamError("device registration is rate-limited to once per minute; please retry shortly")
}

// waitRegGen 等待一次注册完成,返回新设备与其代次。
func (m *deviceManager) waitRegGen(ctx context.Context, ch chan struct{}) (*nativeDevice, uint64, error) {
	select {
	case <-ch:
	case <-ctx.Done():
		return nil, 0, parseerr.UpstreamError("timed out waiting for device registration: " + ctx.Err().Error())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.device != nil && !m.invalid {
		return m.device, m.gen, nil
	}
	if m.regErr != nil {
		return nil, 0, parseerr.UpstreamError("device registration failed: " + m.regErr.Error())
	}
	return nil, 0, parseerr.UpstreamError("device registration did not produce a usable device")
}

// waitReg 同 waitRegGen,只返回错误(启动预热用,设备从状态读)。
func (m *deviceManager) waitReg(ctx context.Context, ch chan struct{}) (*nativeDevice, error) {
	dev, _, err := m.waitRegGen(ctx, ch)
	return dev, err
}

// publish 发布一个刚注册好的设备(新代次)。用于 /api/v2/register 端点的
// 显式注册结果发布(操作者主动行为,不受阈值约束)。
func (m *deviceManager) publish(dev *nativeDevice) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.device = dev
	m.gen++
	m.invalid = false
	m.regErr = nil
}

// cooldownRemainingLocked 返回距下次允许启动注册的剩余时间(已可启动时为 ≤0)。
func (m *deviceManager) cooldownRemainingLocked() time.Duration {
	if m.lastRegAt.IsZero() {
		return 0
	}
	return deviceRegMinInterval - time.Since(m.lastRegAt)
}

// tryStartRegLocked 尝试启动注册(调用方持有 m.mu)。返回语义:
//   - 已有注册在跑:返回其完成 channel(调用方等它跑完取结果,不另起注册);
//   - 阈值冷却中:返回 nil(未启动,无注册可等);
//   - 否则:启动新注册并返回其完成 channel。
//
// 注册用独立 context:任何一个等待请求取消都不应中断共享的注册流程。
func (m *deviceManager) tryStartRegLocked() chan struct{} {
	if m.regCh != nil {
		return m.regCh
	}
	if m.cooldownRemainingLocked() > 0 {
		return nil
	}
	ch := make(chan struct{})
	m.regCh = ch
	m.lastRegAt = time.Now()
	go func() {
		dev, err := registerDeviceFull(context.Background())
		m.mu.Lock()
		m.regCh = nil
		if err == nil {
			m.device = dev
			m.gen++
			m.invalid = false
			m.regErr = nil
			log.Printf("[device-mgr] 注册成功,发布新设备 gen=%d (did=%s)", m.gen, dev.DeviceID)
		} else {
			m.regErr = err
			log.Printf("[device-mgr] 注册失败: %v", err)
		}
		close(ch)
		m.mu.Unlock()
	}()
	return ch
}
