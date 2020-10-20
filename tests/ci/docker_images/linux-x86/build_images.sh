#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

docker build -t ubuntu-16.04:gcc-5x ubuntu-16.04_gcc-5x
docker build -t ubuntu-18.04:gcc-7x ubuntu-18.04_gcc-7x
docker build -t ubuntu-18.04:clang-6x ubuntu-18.04_clang-6x
docker build -t ubuntu-19.04:gcc-8x ubuntu-19.04_gcc-8x
docker build -t ubuntu-19.04:clang-8x ubuntu-19.04_clang-8x
docker build -t ubuntu-19.10:gcc-9x ubuntu-19.10_gcc-9x
docker build -t ubuntu-19.10:clang-9x ubuntu-19.10_clang-9x
docker build -t ubuntu-19.10:sanitizer ubuntu-19.10_clang-9x_sanitizer
docker build -t centos-7:gcc-4x centos-7_gcc-4x
docker build -t amazonlinux-2:gcc-7x amazonlinux-2_gcc-7x
docker build -t fedora-31:gcc-9x fedora-31_gcc-9x
docker build -t fedora-31:clang-9x fedora-31_clang-9x
docker build -t integration:s2n s2n_integration_clang-9x
docker build -t ubuntu-20.04:gcc-9x ubuntu-20.04_gcc-9x
docker build -t ubuntu-20.04:clang-10x ubuntu-20.04_clang-10x
