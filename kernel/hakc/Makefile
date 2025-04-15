obj-$(CONFIG_HAKC) += hakc_common.o hakc_global_init.o

ifneq ($(CONFIG_HAKC_ARM_V9), y)
	ifneq ($(CONFIG_HAKC_ARM_V8_MEMORY), y)
		ifneq ($(CONFIG_HAKC_ARM_V8_BTREE), y)
			ifneq ($(CONFIG_HAKC_X86_MEMORY), y)
				ifneq ($(CONFIG_HAKC_X86_BTREE), y)
					ifeq ($(CONFIG_HAKC_ARM_V8), y)
						$(error "HAKC ARM V8 set but no tagging type specified!")
					endif
					ifeq ($(CONFIG_HAKC_X86), y)
						$(error "HAKC X86 set but not tagging type specified!")
					endif
				endif
			endif
		endif
	endif

	obj-$(CONFIG_HAKC_ARM_V8_MEMORY) += hakc_noarch_tag_memory.o
	obj-$(CONFIG_HAKC_X86_MEMORY) += hakc_noarch_tag_memory.o
	obj-$(CONFIG_HAKC_ARM_V8_BTREE) += hakc_noarch_tag_btree.o
	obj-$(CONFIG_HAKC_X86_BTREE) += hakc_noarch_tag_btree.o
endif
