package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/WangSirMe/tiktok-android-signer/native"
)

// 演示 Android 原生纯算法路径:设备注册 → get_token/msToken → 签名 multi detail → 输出视频信息
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: demo <视频数字ID(aweme_id)>")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	item, err := native.FetchViaNativeAppAPI(ctx, os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "解析失败:", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(item, "", "  ")
	fmt.Println(string(out))
}
