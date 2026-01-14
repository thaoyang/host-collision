#!/bin/bash

# 检查参数数量
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <sld> <t>"
    exit 1
fi

# 获取参数
SLD=$1
T=$2

# 确保log1目录存在
mkdir -p log1

# 运行程序，同时重定向标准输出和标准错误
nohup go run hostCollision.go -sld "$SLD" -t "$T" > "log1/$SLD.log" 2>&1 &
echo "Start running: hostCollision.go -sld $SLD -t $T"