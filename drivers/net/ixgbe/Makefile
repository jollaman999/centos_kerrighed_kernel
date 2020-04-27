# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 1999 - 2019 Intel Corporation.

#
# Makefile for the Intel(R) 10GbE PCI Express Linux Network Driver
#

obj-$(CONFIG_IXGBE) += ixgbe.o

ixgbe-objs := 	ixgbe_main.o \
	ixgbe_api.o \
	ixgbe_common.o \
	ixgbe_dcb.o \
	ixgbe_dcb_82598.o \
	ixgbe_dcb_82599.o \
	ixgbe_ethtool.o \
	ixgbe_lib.o \
	ixgbe_mbx.o \
	ixgbe_sriov.o \
	ixgbe_param.o \
	ixgbe_phy.o \
	ixgbe_procfs.o \
	ixgbe_82598.o \
	ixgbe_82599.o \
	ixgbe_x540.o \
	ixgbe_x550.o \
	kcompat.o

ixgbe-$(CONFIG_IXGBE_DCB) +=  ixgbe_dcb_nl.o
ixgbe-$(CONFIG_DEBUG_FS) +=  ixgbe_debugfs.o
ixgbe-$(CONFIG_FCOE) +=  ixgbe_fcoe.o
ixgbe-$(CONFIG_PTP_1588_CLOCK) += ixgbe_ptp.o
ixgbe-$(CONFIG_SYSFS) += ixgbe_sysfs.o
