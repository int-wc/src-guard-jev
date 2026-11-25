#!/usr/bin/env bash
# src-guard-jev 安装脚本
set -euo pipefail

PREFIX="${PREFIX:-/opt/src-guard-jev}"
echo "安装到: $PREFIX"

if [ ! -f requirements.txt ]; then
  echo "请在仓库根目录运行" >&2; exit 1
fi

echo "[1/4] 安装 Python 依赖"
pip install -r requirements.txt

echo "[2/4] 拷贝文件到 $PREFIX"
mkdir -p "$PREFIX"
cp -r core ui healthsvc probes examples "$PREFIX"/

echo "[3/4] 准备配置"
if [ ! -f "$PREFIX/scopes.json" ]; then
  cp examples/scopes.example.json "$PREFIX/scopes.json"
  echo "  已生成 $PREFIX/scopes.json —— 请填入你有授权的目标域名"
fi

echo "[4/4] 提示"
echo "  1. 设置 JEV_API_KEY 环境变量"
echo "  2. 参考 deploy/*.service.example 配置 systemd"
echo "  3. 把 mitmproxy CA 证书装进目标程序的信任链"
