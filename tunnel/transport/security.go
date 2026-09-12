package transport

import (
	"github.com/Potterli20/trojan-go-fork/common"
)

// validatePluginCommand 校验传输插件命令和参数的安全性。
// 检查命令非空、命令路径和参数不包含路径遍历序列（".."）。
// exec.Command 不经过 shell，shell 元字符不构成注入风险。
func validatePluginCommand(cmd string, args []string) error {
	// 校验命令非空
	if cmd == "" {
		return common.NewError("transport plugin command is empty")
	}
	// 校验命令路径不包含遍历序列
	if _, err := common.ValidateFilePath(cmd); err != nil {
		return common.NewError("transport plugin command path validation failed").Base(err)
	}
	// 校验每个参数不包含遍历序列
	for _, arg := range args {
		if err := common.SanitizeCommandArg(arg); err != nil {
			return common.NewError("transport plugin argument validation failed").Base(err)
		}
	}
	return nil
}
