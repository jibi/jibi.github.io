+++
title = "XDP without eBPF (aka learning some Rust LKM)"
date = 2026-03-04
description = "Running packet processing code in the XDP fast path from a Rust loadable kernel module, bypassing eBPF and its verifier."
+++

It's been about 10 years since [XDP was born at Netdev Conf 1.1 in Seville](https://medium.com/@tom_84912/happy-birthday-xdp-a971b8ac75e6)!

While I wasn't involved in the design of the technical bits (I barely knew any Linux kernel networking internals, skb details, etc. at the time), I was there giving my first talk, or rather my first [BoF session](https://netdevconf.info/1.1/proceedings/slides/dangaard-network-performance.pdf), on that subject, discussing what we believed at Cloudflare was needed from the kernel for something that would later become XDP, based on our experience with similar frameworks:

* Processing packets at the very lowest layer, skipping all the network stack overhead
* Filtering directly on the NIC RX ring (a circular buffer), avoiding skb allocation and a lot of costly `kmalloc()` / `kfree()`
* The ability to run safe programs (BPF) to decide whether traffic should be allowed or not

eBPF was of course the obvious choice, and the amount of infrastructure and projects built around XDP/eBPF since then has been impressive. But I started wondering: is there a way to reuse that same cool XDP infrastructure without all the eBPF ~limitations :P~ constraints? Of course those are there for a reason, but let's pretend we know what we are doing: can we run some code in the XDP path without the verifier vetoing its soundness?

This thought is not new: some time ago I wrote a [POC](https://github.com/jibi/xdp-rust-kernel-patch) to run Rust code linked to a regular C Linux kernel module in the XDP path instead of the usual eBPF bytecode. It was a fun experiment, but it required patching and recompiling the kernel to add a new function pointer that the XDP path could call. Wouldn't it be nicer if we didn't need to recompile the kernel?

I've been reading about (and then mostly neglecting) Rust kernel development for far too long, so I figured it was time to give it a shot. Reworking that POC into a Rust LKM that runs in the XDP path without patching/recompiling the whole kernel felt like a good place to start.

Now, I can think of at least a couple of ways to run arbitrary code in the XDP path without recompiling the kernel:

* (Live)patch the XDP dispatcher to execute our code instead of whatever is in the `bpf_func` pointer
* Populate a `struct bpf_prog`, point its `bpf_func` at our code, and pass that struct to `dev_xdp_install()`

We can give both approaches a try. Livepatching has the nice property that something else sets up XDP for us (we just redirect the execution of the eBPF program), but the downside is that we still have to do the whole eBPF compile/load/verify ritual for a program that will never run. The second option is self contained in a Rust module, but the NIC might end up in a partially configured XDP state (e.g. I don't even know if `ip link` will report `xdp` being enabled).

Let's start with the first one. Regarding livepatching, we have at least a couple of options here as well: livepatch would be the cleaner production tool, but unfortunately it's disabled by default on NixOS, and ftrace is the livepatch underlying mechanism anyway, so we'll go with that.

So here's the plan: enable XDP on an interface, patch the dispatcher with ftrace, then rewrite the module in Rust.

## Enabling XDP

As I mentioned, in order to enable XDP on a given interface we need to load an eBPF program, which in our case will be a dummy one that constantly returns `XDP_PASS` (easy):

```
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

Next we can enter the `xdp-dev` dev shell defined in a `flake.nix` that looks something like:

```
{
  description = "Rust XDP Nix dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, ... }:
    let
    system = "x86_64-linux";
  pkgs = import nixpkgs { inherit system; };
  in {
    devShells.${system} = {
      xdp-dev = pkgs.mkShell {
        name = "xdp-dev";
        buildInputs = with pkgs; [
          iproute2
            libbpf
            linuxHeaders
            llvmPackages.clang-unwrapped
            llvmPackages.llvm
            pkg-config
        ];
        shellHook = ''
          export CFLAGS="$CFLAGS -I$(pkg-config --variable=includedir libbpf)"
          export CFLAGS="$CFLAGS -I${pkgs.linuxHeaders}/include"
          '';
      };
    };
  };
}
```

build/load the eBPF program:

```
➜  xdp_prog git:(master) nix develop ..#xdp-dev -c $SHELL
➜  xdp_prog git:(master) clang -O2 -g -target bpf $CFLAGS -c xdp_prog.c -o xdp_prog.o
➜  xdp_prog git:(master) sudo ip link set dev wlp0s20f3 xdp obj xdp_prog.o sec xdp
```

and traffic, as expected, will be unaffected:

```
64 bytes from 192.168.1.1: icmp_seq=31 ttl=64 time=3.19 ms
64 bytes from 192.168.1.1: icmp_seq=32 ttl=64 time=3.26 ms
```

But that's boring, and it requires us to pull in a full clang/LLVM toolchain just to put together an ELF with literally two instructions (`r0 = 2`, `exit`), so let's build it from scratch without external dependencies.

As mentioned, we need just a couple of instructions:

```
let prog = [BpfInsn::mov32_imm(0, XDP_PASS), BpfInsn::exit()];
```

and a couple of BPF syscalls (and related struct definitions for the `BpfAttrProgLoad` and `BpfAttrLinkCreate` attributes) to load and attach the XDP program:

```
Bpf::syscall(
    Self::BPF_PROG_LOAD,
    &attr as *const _ as *const c_void,
    mem::size_of::<BpfAttrProgLoad>(),
)
..
Bpf::syscall(
    Self::BPF_LINK_CREATE,
    &link_attr as *const _ as *const c_void,
    mem::size_of::<BpfAttrLinkCreate>(),
)
```

This is also a good chance to test the newer `BPF_LINK_CREATE` syscall rather than the usual netlink approach (ok, maybe not that new, as it's been around for ~6 years).

Next, we build it with `rustc` and we're ready to run it:

```
➜  enable-xdp git:(master) nix develop nixpkgs#rustc -c $SHELL
➜  enable-xdp git:(master) rustc enable-xdp.rs
➜  enable-xdp git:(master) sudo ./enable-xdp wlp0s20f3
```

(I renamed the tool to `enable-xdp` so loading a dummy eBPF program just to toggle XDP can remain an implementation detail, we can pretend it never happened and we can move on with our day :D).

To quickly test if this thing is working, we can make it return `XDP_DROP`. And as we load it, we can see ingress traffic starts getting dropped:

```
64 bytes from 192.168.1.1: icmp_seq=21 ttl=64 time=3.45 ms
64 bytes from 192.168.1.1: icmp_seq=22 ttl=64 time=3.10 ms
From 192.168.1.120 icmp_seq=46 Destination Host Unreachable
From 192.168.1.120 icmp_seq=47 Destination Host Unreachable
```

## LKM on NixOS

Since I've never done LKM development in Rust, on NixOS, or tried ftrace, let's go step by step.

First let's make sure we can build an LKM in a non FHS system. Turns out the only tricky part was figuring out the right package and pointing our Makefile to the correct kernel dir. Here's the `kernel-dev` dev shell from `flake.nix`:

```
kernel-dev = pkgs.mkShell {
  name = "kernel-dev";
  buildInputs = with pkgs; [
    linux_latest.dev
  ];
  shellHook = ''
    export KERNEL_DIR=${pkgs.linux_latest.dev}/lib/modules/$(uname -r)/build
    '';
};
```

then the usual Makefile:

```
obj-m += xdp_ftrace_c.o

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
```

a dummy module:

```
#include <linux/module.h>
static int __init ftrace_hook_init(void) { return 0; }
static void __exit ftrace_hook_exit(void) {}
module_init(ftrace_hook_init);
module_exit(ftrace_hook_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ftrace example");
```

and `make`:

```
➜  xdp_ftrace_c git:(master) nix develop ..#kernel-dev -c $SHELL
➜  xdp_ftrace_c git:(master) make
..
  LD [M]  xdp_ftrace_c.ko
```

Great, we have a `.ko` object. Next stop: figuring out ftrace.

## Meet ftrace

ftrace is a kernel framework that lets us hook into almost any kernel function (with a few exceptions like `__always_inline` and `notrace`).

A kernel with ftrace support is compiled with the `-mfentry` compiler option which adds a trampoline to the prologue of every traceable function: in practice just a `call __fentry__` so that all functions will jump to this instrumentation function which can then do various things (in userspace it can be used for example for profiling) and then we return back to the original function.

For performance reasons, as an extra call/ret pair for each function invocation adds quite some overhead, at runtime the kernel replaces all those `call __fentry__` with five NOP bytes. Then, when tracing is enabled, those NOPs get overwritten with the actual ftrace trampoline call only for the functions that need instrumentation.

For more details there are various talks from the author, like [this one](https://www.youtube.com/watch?v=93uE_kWWQjs). It's interesting how it works on x86, as atomically overwriting 5 bytes in the text section requires a bit of a magical dance with multiple passes when dealing with SMP (as instructions can cross cache/page boundaries):

* The first of the five NOP bytes is overwritten with an `int3` breakpoint instruction (then a memory barrier syncs all CPUs on that). This breakpoint jumps to an ftrace handler that increments the IP by 5 bytes so the CPU is effectively back to executing the traced function as if nothing happened
* Then the other 4 bytes are overwritten with the address of the ftrace trampoline (then another memory barrier)
* Then the `int3` instruction, which is just a single byte, can be atomically replaced with the `call` instruction's opcode

The talk mentions it took Intel engineers a few months to reluctantly accept this would work :D Anyway, we'll look a bit more into the details later on.

### ftrace API

First we need to define a filter that tells ftrace when to run our callback, basically specify what we want to instrument and which callback to run:

```
static struct ftrace_ops
my_fops = {
  .func = my_cb,
};

ftrace_set_filter(&my_fops, "some_func", 0, 0);
register_ftrace_function(&my_fops);
```

then we define the actual callback in which we can inspect registers, parent caller, do printk, go crazy etc.:

```
static void notrace
my_cb(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct ftrace_regs *fregs) {
..
}
```

In addition to inspecting the function state through its registers, we can also edit them. Changing the instruction pointer is exactly what we need to do in order to hijack the execution of the XDP dispatcher to our own function. We can do that with:

```
ftrace_regs_set_instruction_pointer(fregs, (unsigned long)some_func_hook);
```

where `some_func_hook` will have the same signature as the instrumented function.

But what are we going to instrument?

### Finding our XDP target

We now need to find a good target to patch, ideally the logic that only runs the bpf program. `bpf_prog_run_xdp` appears to be the entry point for both generic `SKB_MODE` and native `DRV_MODE`:

```
static __always_inline u32 bpf_prog_run_xdp(const struct bpf_prog *prog,
					    struct xdp_buff *xdp)
{
...
	u32 act = __bpf_prog_run(prog, xdp, BPF_DISPATCHER_FUNC(xdp));
```

`BPF_DISPATCHER_FUNC` is just a macro that returns the name of the XDP dispatcher function:

```
#define BPF_DISPATCHER_FUNC(name) bpf_dispatcher_##name##_func
```

The actual dispatcher is defined using the `DEFINE_BPF_DISPATCHER` macro:

```
#define DEFINE_BPF_DISPATCHER(name)					\
	__BPF_DISPATCHER_SC(name);					\
	noinline __bpfcall unsigned int bpf_dispatcher_##name##_func(	\
		const void *ctx,					\
		const struct bpf_insn *insnsi,				\
		bpf_func_t bpf_func)					\
	{								\
		return __BPF_DISPATCHER_CALL(name);			\
	}								\
```

and then called with `__BPF_DISPATCHER_CALL`:

```
#define __BPF_DISPATCHER_CALL(name)				\
	static_call(bpf_dispatcher_##name##_call)(ctx, insnsi, bpf_func)
```

so our target function is `bpf_dispatcher_xdp_func`.

## Putting everything together (in C)

We should now have everything to put together a C LKM that patches `bpf_dispatcher_xdp_func`.

Here's a slightly stripped down version (and here the [full version](https://github.com/jibi/xdp-rust-lkm/blob/master/xdp_ftrace_c/xdp_ftrace_c.c)):

```
static noinline notrace __bpfcall unsigned int
xdp_force_pass(const void *ctx, const struct bpf_insn *insnsi, bpf_func_t bpf_func)
{
	return XDP_PASS;
}

static void notrace bpf_dispatcher_xdp_func_cb(unsigned long ip, unsigned long parent_ip,
					       struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	ftrace_regs_set_instruction_pointer(fregs, (unsigned long)xdp_force_pass);
}

static struct ftrace_ops bpf_dispatcher_xdp_func_fops = {
	.func = bpf_dispatcher_xdp_func_cb,
	.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY,
};

static int __init ftrace_hook_init(void)
{
	int ret;

	ret = ftrace_set_filter(&bpf_dispatcher_xdp_func_fops, "bpf_dispatcher_xdp_func", 0, 0);
	if (ret) {
		return ret;
	}

	ret = register_ftrace_function(&bpf_dispatcher_xdp_func_fops);
	if (ret) {
		ftrace_set_filter(&bpf_dispatcher_xdp_func_fops, NULL, 0, 0);
		return ret;
	}

	return 0;
}
```

let's build it and load it:

```
➜  xdp_ftrace_c git:(master) sudo insmod ./xdp_ftrace_c.ko
```

and we can confirm that the ftrace livepatch is working by looking at the traffic that starts flowing again, as the dispatcher is now returning `XDP_PASS` rather than the eBPF program's `XDP_DROP`:

```
From 192.168.1.120 icmp_seq=13 Destination Host Unreachable
From 192.168.1.120 icmp_seq=14 Destination Host Unreachable
64 bytes from 192.168.1.1: icmp_seq=21 ttl=64 time=2.13 ms
64 bytes from 192.168.1.1: icmp_seq=22 ttl=64 time=1.10 ms
```

### Digging into ftrace internals

Let's do a quick detour and peek into the ftrace internals: I wanted to see how the trampoline actually works and get a sense of the cost of doing livepatching.

Let's start by looking at the kernel object:

```
➜  ~ gdb -q $(nix-store -q --outputs $(nix-store -q -d /run/booted-system/kernel) | rg dev -m1)/vmlinux
Reading symbols from /nix/store/b4kf7sphmydjzswhm3yyn90qj2a7v4iv-linux-6.19-dev/vmlinux...
(gdb) disassemble bpf_dispatcher_xdp_func
Dump of assembler code for function bpf_dispatcher_xdp_func:
   0xffffffff81e2a2f0 <+0>:	endbr64
   0xffffffff81e2a2f4 <+4>:	call   0xffffffff812e7bf0 <__fentry__>
```

after the `endbr64` instruction (which has nothing to do with ftrace, it just allows the function to be targeted by an indirect jump without faulting) we can see in the kernel image, as expected, that our target function has in its prologue the `call __fentry__` emitted by `gcc -mfentry`.

If we inspect the running image though, we should see that it got replaced with NOPs. Let's first get comfy with gdb by making it use the symbols for the live kernel:

```
TEXT=0x$(sudo awk '/ _stext$/{print $1}' /proc/kallsyms)
VMLINUX=$(nix-store -q --outputs $(nix-store -q -d /run/booted-system/kernel) | rg dev -m1)/vmlinux

sudo gdb -q -c /proc/kcore -ex "set confirm off" -ex "add-symbol-file $VMLINUX $TEXT"
```

Here's the same function on a live kernel:

```
(gdb) disassemble bpf_dispatcher_xdp_func
Dump of assembler code for function bpf_dispatcher_xdp_func:
   0xffffffffa4a2a2f0 <+0>:	endbr64
   0xffffffffa4a2a2f4 <+4>:	nopl   0x0(%rax,%rax,1)
```

we can see that the call has been patched by the kernel with NOPs, so there's virtually no cost.

After loading our kernel module, which enables the tracing callback for `bpf_dispatcher_xdp_func`, those NOPs get overwritten:

```
TEXT=0x$(sudo awk '/ _stext$/{print $1}' /proc/kallsyms)
VMLINUX=$(nix-store -q --outputs $(nix-store -q -d /run/booted-system/kernel) | rg dev -m1)/vmlinux
MODTEXT=$(sudo cat /sys/module/xdp_ftrace_c/sections/.text)
MOD=~/xdp-rust-lkm/xdp_ftrace_c/xdp_ftrace_c.ko

sudo gdb -q -c /proc/kcore -ex "set confirm off" -ex "add-symbol-file $VMLINUX $TEXT" -ex "add-symbol-file $MOD $MODTEXT"
..
(gdb) disassemble bpf_dispatcher_xdp_func
Dump of assembler code for function bpf_dispatcher_xdp_func:
   0xffffffffa4a2a2f0 <+0>:	endbr64
   0xffffffffa4a2a2f4 <+4>:	call   0xffffffffc2b19000
```

if we check `0xffffffffc2b19000`, we'll see we jump to an ftrace trampoline: in our specific case, [`ftrace_regs_caller`](https://elixir.bootlin.com/linux/v6.19-rc5/source/arch/x86/kernel/ftrace_64.S#L201) as we requested access to traced function registers (with `FTRACE_OPS_FL_SAVE_REGS`).

It's probably easier to follow the kernel sources, but in short the trampoline is saving some registers in the `ftrace_regs` struct:

```
(gdb) x/40i 0xffffffffc2b19000
   0xffffffffc2b19000:	pushf
   0xffffffffc2b19001:	sub    $0xa8,%rsp
   0xffffffffc2b19008:	mov    %rax,0x50(%rsp)
   0xffffffffc2b1900d:	mov    %rcx,0x58(%rsp)
   0xffffffffc2b19012:	mov    %rdx,0x60(%rsp)
   0xffffffffc2b19017:	mov    %rsi,0x68(%rsp)
   0xffffffffc2b1901c:	mov    %rdi,0x70(%rsp)
   0xffffffffc2b19021:	mov    %r8,0x48(%rsp)
   0xffffffffc2b19026:	mov    %r9,0x40(%rsp)
   0xffffffffc2b1902b:	movq   $0x0,0x78(%rsp)
   0xffffffffc2b19034:	mov    %rbp,%rdx
   0xffffffffc2b19037:	mov    %rdx,0x20(%rsp)
```

setting the `ip` (`%rdi`) and `parent_ip` (`%rsi`) callback args:

```
   0xffffffffc2b1903c:	mov    0xb8(%rsp),%rsi
   0xffffffffc2b19044:	mov    0xb0(%rsp),%rdi
   0xffffffffc2b1904c:	mov    %rdi,0x80(%rsp)
   0xffffffffc2b19054:	sub    $0x5,%rdi
   0xffffffffc2b19058:	cs nopl 0x0(%rax,%rax,1)
```

setting the `struct ftrace_ops` callback's arg (it's referenced relative to the `%rip` register, so this must be a trampoline generated dynamically?):

```
   0xffffffffc2b19061:	mov    0xf6(%rip),%rdx        # 0xffffffffc2b1915e
```

saving some other registers and setting some other fields in the `ftrace_ops` struct:

```
   0xffffffffc2b19068:	mov    %r15,(%rsp)
   0xffffffffc2b1906c:	mov    %r14,0x8(%rsp)
   0xffffffffc2b19071:	mov    %r13,0x10(%rsp)
   0xffffffffc2b19076:	mov    %r12,0x18(%rsp)
   0xffffffffc2b1907b:	mov    %r11,0x30(%rsp)
   0xffffffffc2b19080:	mov    %r10,0x38(%rsp)
   0xffffffffc2b19085:	mov    %rbx,0x28(%rsp)
   0xffffffffc2b1908a:	mov    0xa8(%rsp),%rcx
   0xffffffffc2b19092:	mov    %rcx,0x90(%rsp)
   0xffffffffc2b1909a:	mov    $0x18,%rcx
   0xffffffffc2b190a1:	mov    %rcx,0xa0(%rsp)
   0xffffffffc2b190a9:	mov    $0x10,%rcx
   0xffffffffc2b190b0:	mov    %rcx,0x88(%rsp)
   0xffffffffc2b190b8:	lea    0xb8(%rsp),%rcx
   0xffffffffc2b190c0:	mov    %rcx,0x98(%rsp)
   0xffffffffc2b190c8:	lea    (%rsp),%rcx
   0xffffffffc2b190cc:	cs nopl 0x0(%rax,%rax,1)
```

and calling into the next function:

```
   0xffffffffc2b190d5:	call   0xffffffffa4092080 <ftrace_ops_assist_func>
```

which is another ftrace helper used mostly to deal with safe recursion of the tracing logic (as we requested with the `FTRACE_OPS_FL_RECURSION` flag). Eventually, this helper calls into a single instruction stub:

```
(gdb) disassemble ftrace_ops_assist_func
Dump of assembler code for function ftrace_ops_assist_func:
..
   0xffffffffa4092100 <+128>:	mov    (%rdx),%rax
   0xffffffffa4092103 <+131>:	call   0xffffffffc0401d70
```

that does an indirect `%rax` jump:

```
(gdb) x/i 0xffffffffc0401d70
   0xffffffffc0401d70:	jmp    *%rax
```

which, as we saw, contains our `ftrace_ops` struct (it was assigned to `%rdx` in `ftrace_regs_caller`) and the first field of this struct (`func`) is pointing exactly to our `bpf_dispatcher_xdp_func_cb` hook:

```
(gdb) p **(struct ftrace_ops **) 0xffffffffc2b1915e
$1 = {func = 0xffffffffc2afe030 <bpf_dispatcher_xdp_func_cb>, next = 0xffff8e24c56ac400, flags = 6231, private = 0x0,
```

As we know, this function just calls `ftrace_regs_set_instruction_pointer` to set the saved `%rip` in the `ftrace_regs` struct (the third arg/`%rcx` register of the callback) to the address of the `xdp_force_pass` function:

```
(gdb) disassemble bpf_dispatcher_xdp_func_cb
Dump of assembler code for function bpf_dispatcher_xdp_func_cb:
   0xffffffffc2afe030 <+64>:	endbr64
   0xffffffffc2afe034 <+68>:	movq   $0xffffffffc2afe010,0x80(%rcx)
   0xffffffffc2afe03f <+79>:	xor    %ecx,%ecx
   0xffffffffc2afe041 <+81>:	jmp    0xffffffffa4cacce0 <its_return_thunk>
..
(gdb) info symbol 0xffffffffc2afe010
xdp_force_pass in section .text of /home/jibi/xdp-rust-lkm/xdp_ftrace_c/xdp_ftrace_c.ko
```

then we jump to a `ret` instruction:

```
(gdb) disassemble its_return_thunk
Dump of assembler code for function its_return_thunk:
   0xffffffffa4cacce0 <+0>:	ret
```

which returns to `ftrace_ops_assist_func` (since it got there via a `call` into the `jmp *%rax` trampoline), which then returns to the initial trampoline.

From there we restore all the registers from the `ftrace_regs` struct, overwriting `%rip` with the `xdp_force_pass` function's address, and effectively redirecting the control flow to our target function once we return from the trampoline:

```
(gdb) x/30i 0xffffffffc2b19000+0xd5
   0xffffffffc2b190d5:	call   0xffffffffa4092080 <ftrace_ops_assist_func>
..
   0xffffffffc2b190ea:	mov    0x80(%rsp),%rax
   0xffffffffc2b190f2:	mov    %rax,0xb0(%rsp)
..
   0xffffffffc2b19151:	add    $0xa8,%rsp
   0xffffffffc2b19158:	popf
   0xffffffffc2b19159:	jmp    0xffffffffa4cacce0 <its_return_thunk>
```

To sum up: `bpf_dispatcher_xdp_func` -> `ftrace_regs_caller` trampoline -> `ftrace_ops_assist_func` helper -> `bpf_dispatcher_xdp_func_cb` (our hook) which overwrites the saved IP in `ftrace_regs` -> `ret` back to `ftrace_regs_caller` which restores registers and resumes execution at the address we patched (`xdp_force_pass`).

I have to admit I naively assumed the whole patching dance would be more straightforward, but after going through it, it makes sense that we want to preserve registers, be careful about recursion, and all the other things.

Now that we understand the trampoline and the cost model, let's port it to Rust.

## Let it Rust

Let's start by getting a dummy module to compile. We can take a look at the [templates](https://github.com/Rust-for-Linux/rust-out-of-tree-module) in the Rust for Linux repo:

```
module! {
    type: XdpFtrace,
    name: "xdp_ftrace_rust",
    authors: ["jibi"],
    description: "Rust ftrace XDP POC",
    license: "GPL",
}

struct XdpFtrace {}

impl kernel::Module for XdpFtrace {
    fn init(_module: &'static ThisModule) -> Result<Self> {
      pr_info!("Loading Rust ftrace XDP POC");

      Ok(XdpFtrace {})
    }
}

impl Drop for XdpFtrace {
    fn drop(&mut self) {
      pr_info!("Unloading Rust ftrace XDP POC");
    }
}
```

Makefile is surprisingly identical to a C makefile:

```
obj-m := xdp_ftrace_rust.o
```

so all that's left is to add a `rustc` to our previous `kernel-dev` Nix dev shell:

```
buildInputs = with pkgs; [
  linux_latest.dev
    rustc-unwrapped
];
```

and our module will build just fine:

```
➜  xdp_ftrace_rust git:(master) nix develop ..#kernel-dev -c $SHELL
➜  xdp_ftrace_rust git:(master) make
make -C /nix/store/b4kf7sphmydjzswhm3yyn90qj2a7v4iv-linux-6.19-dev/lib/modules/6.19.0/build M=/home/jibi/xdp-rust-lkm/xdp_ftrace_rust modules
..
  LD [M]  xdp_ftrace_rust.ko
```

## Bindings bindings bindings

Now we need to call into ftrace from Rust:

```
➜  linux-6.19 rg ftrace -i rust
➜  linux-6.19
```

Oh no.

Unfortunately there are no ftrace Rust bindings available, so we need to get a bit creative.

First option is to implement them by hand: add a bunch of `extern "C"` declarations for `ftrace_set_filter()`, `register_ftrace_function()`, etc. (easy but manual work I'd rather avoid) and rewrite all the relevant types needed by ftrace. That can get a bit hairy (euphemism) quite fast, due to inner structs, Linux kernel lists, #ifdefs, and the like.

So let's try to generate Rust bindings with `bindgen`. Here we also have a couple of options: we can create a dummy bindings.h file which includes ftrace.h, or we can rely on BTF symbols:

```
➜  ~ bpftool btf dump file /sys/kernel/btf/vmlinux format c | rg 'struct ftrace_ops \{|ftrace_set_filter|register_ftrace_function'
struct ftrace_ops {
```

Unfortunately, while BTF does include function prototypes, `bpftool` only exposes them in the raw format, which means we would either have to parse and resolve type IDs by hand to recover the actual C signatures, or we'd need to write the function declarations by ourselves:

```
extern "C" {
    fn ftrace_set_filter(
        ops: *mut ftrace_ops,
        buf: *const c_char,
        len: c_int,
        reset: c_int,
    ) -> c_int;
    fn register_ftrace_function(ops: *mut ftrace_ops) -> c_int;
    fn unregister_ftrace_function(ops: *mut ftrace_ops) -> c_int;
}
```

although both could work, I'd prefer a generic solution that doesn't require me to manually parse `bpftool btf` or figure out/translate each time the signature of whatever function I need next, so we'll go with the `#include <linux/ftrace.h>` approach.

Surely we can simply create a header file with:

```
#include <linux/ftrace.h>
```

add bindgen to our Nix dev shell:

```
buildInputs = with pkgs; [
  linux_latest.dev
    rust-bindgen-unwrapped
    rustc-unwrapped
];
```

and bindgen will do its magic, right?

```
➜  xdp_ftrace_rust git:(master) bindgen ./bindings.h
./bindings.h:4:10: fatal error: 'linux/ftrace.h' file not found
Unable to generate bindings: clang diagnosed error: ./bindings.h:4:10: fatal error: 'linux/ftrace.h' file not found
```

Almost. Let's move to the Makefile and start adding some includes, as the kernel headers are not part of the standard headers:

```
BINDGEN_CLANG_FLAGS := -- \
    -I$(KERNEL_SRC)/include \
    -I$(KERNEL_SRC)/arch/$(ARCH)/include \
    -I$(KERNEL_SRC)/include/uapi \
    -I$(KERNEL_BUILD)/include \
    -I$(KERNEL_BUILD)/arch/$(ARCH)/include/generated
```

should be much better now:

```
➜  xdp_ftrace_rust git:(master) make $(pwd)/bindings.rs
bindgen /home/jibi/xdp-rust-lkm/xdp_ftrace_rust/bindings.h
/nix/store/b4kf7sphmydjzswhm3yyn90qj2a7v4iv-linux-6.19-dev/lib/modules/6.19.0/build/source/include/linux/compiler_attributes.h:55:9: warning: '__always_inline' macro redefined [-Wmacro-redefined]
/nix/store/b4kf7sphmydjzswhm3yyn90qj2a7v4iv-linux-6.19-dev/lib/modules/6.19.0/build/source/include/uapi/linux/stddef.h:10:9: note: previous definition is here
/nix/store/b4kf7sphmydjzswhm3yyn90qj2a7v4iv-linux-6.19-dev/lib/modules/6.19.0/build/source/include/asm-generic/rwonce.h:64:8: error: unknown type name '__no_sanitize_or_inline'
/nix/store/b4kf7sphmydjzswhm3yyn90qj2a7v4iv-linux-6.19-dev/lib/modules/6.19.0/build/source/include/asm-generic/rwonce.h:82:8: error: unknown type name '__no_sanitize_or_inline'
/nix/store/b4kf7sphmydjzswhm3yyn90qj2a7v4iv-linux-6.19-dev/lib/modules/6.19.0/build/source/include/linux/overflow.h:53:9: error: call to undeclared function 'unlikely'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
..
fatal error: too many errors emitted, stopping now [-ferror-limit=]

make: *** [Makefile:32: /home/jibi/xdp-rust-lkm/xdp_ftrace_rust/bindings.rs] Error 1
```

Never mind, let's cut this game. Here's the full Makefile an hour later (not sure anymore parsing by hand `bpftool btf .. format raw` was that bad of an idea):

making bindgen happy with `no_std`:

```
BINDGEN_FLAGS := \
	--use-core \
	--ctypes-prefix core::ffi \
	--no-layout-tests \
```

selecting only the symbols we actually need:

```
	--allowlist-type 'ftrace_ops' \
	--allowlist-type '__arch_ftrace_regs' \
	--allowlist-var 'FTRACE_OPS_FL_.*' \
	--allowlist-function 'ftrace_set_filter' \
	--allowlist-function 'register_ftrace_function' \
	--allowlist-function 'unregister_ftrace_function' \
```

reassuring the compiler we know what we are doing:

```
	--raw-line '\#![allow(non_camel_case_types)]' \
	--raw-line '\#![allow(non_snake_case)]' \
	--raw-line '\#![allow(non_upper_case_globals)]' \
	--raw-line '\#![allow(dead_code)]' \
	--raw-line '\#![allow(unreachable_pub)]' \
	--raw-line '\#![allow(unnecessary_transmutes)]' \
	--raw-line '\#![allow(unsafe_op_in_unsafe_fn)]' \
	--raw-line '\#![allow(improper_ctypes_definitions)]'
```

setting the C standard and enabling ms extensions for anonymous structs/unions:

```
BINDGEN_CLANG_FLAGS := -- \
	-std=gnu11 \
	-fms-extensions \
```

including the kernel config to have all the features (ifdefs) needed enabled:

```
	-include $(KERNEL_SRC)/include/linux/kconfig.h \
	-include $(KERNEL_BUILD)/include/generated/autoconf.h \
```

adding the usual headers:

```
	-I$(KERNEL_SRC)/include \
	-I$(KERNEL_SRC)/arch/$(ARCH)/include \
	-I$(KERNEL_SRC)/include/uapi \
	-I$(KERNEL_BUILD)/include \
	-I$(KERNEL_BUILD)/arch/$(ARCH)/include/generated \
```

kernel headers are expecting to know the module name for some reason:

```
	-DKBUILD_MODNAME=\"xdp_ftrace_rust\" \
	-DKBUILD_BASENAME=\"xdp_ftrace_rust\" \
```

a bunch of defines we need that would usually be defined by the kernel makefiles:

```
	-D__KERNEL__ \
	-D__TARGET_ARCH_$(ARCH) \
	-DCC_USING_FENTRY \
```

and finally let's suppress some warnings:

```
	-Wno-unknown-attributes \
	-Wno-ignored-attributes \
	-Wno-duplicate-decl-specifier \
	-Wno-address-of-packed-member \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-microsoft-anon-tag
```

Very (not) straightforward. Bindgen will now create a bindings.rs file that we can include in our module:

```
mod bindings;
use bindings::*;
```

and we are ready to build our (still dummy for now) Rust kernel module with all the required ftrace bindings:

```
➜  xdp_ftrace_rust git:(master) make
..
  BTF [M] xdp_ftrace_rust.ko
```

so all that's left to do is port the existing C module to Rust.

## Putting everything together (in Rust)

First let's define a type for our `XdpHook`, the signature of the function that the XDP dispatcher calls:

```
type XdpHook = unsafe extern "C" fn(
    ctx: *const c_void,
    insnsi: *const bpf_insn,
    bpf_func: bpf_func_t,
) -> u32;
```

Then we need a couple of static variables:

```
static mut FTRACE_OPS: ftrace_ops = unsafe { mem::zeroed() };
static XDP_HOOK: AtomicPtr<()> = AtomicPtr::new(null_mut());
```

although it's tempting to store it inside the `XdpFtrace` object, `FTRACE_OPS` needs to be static, as ftrace requires that. Then we have `XDP_HOOK`, which is just a pointer to our hook. It's not strictly needed, but it saves us from hardcoding the hook in the ftrace callback (and so must be protected with `AtomicPtr`).

Then we implement the remaining methods for the `XdpFtrace` object.

The constructor just sets the static `XDP_HOOK` with address of the `XdpHook` function we want to invoke, and calls `register()` to initialize ftrace:

```
impl XdpFtrace {
    const TARGET_FUNC: &[u8] = b"bpf_dispatcher_xdp_func\0";

    fn install_hook(xdp_hook: XdpHook) -> Result<()> {
        XDP_HOOK.store(xdp_hook as *mut (), SeqCst);
        Self::register()
    }
```

`register` is just a 1:1 Rust translation of its C counterpart:

```
    fn register() -> Result<()> {
        let ops = &raw mut FTRACE_OPS;
        unsafe {
            (*ops).func = Some(Self::bpf_dispatcher_xdp_func_cb);
            (*ops).flags = (FTRACE_OPS_FL_SAVE_REGS
                | FTRACE_OPS_FL_RECURSION
                | FTRACE_OPS_FL_IPMODIFY) as c_ulong;
        }

        let ret = unsafe { ftrace_set_filter(ops, Self::TARGET_FUNC.as_ptr() as *mut u8, 0, 0) };
        if ret != 0 {
            pr_err!("ftrace_set_filter failed: {}\n", ret);
            return Err(Error::from_errno(ret));
        }

        let ret = unsafe { register_ftrace_function(ops) };
        if ret != 0 {
            pr_err!("register_ftrace_function failed: {}\n", ret);
            unsafe { ftrace_set_filter(ops, null_mut(), 0, 0) };
            return Err(Error::from_errno(ret));
        }

        Ok(())
    }
```

same for `unregister`:

```
    fn unregister() {
        let ops = &raw mut FTRACE_OPS;
        unsafe {
            unregister_ftrace_function(ops);
            ftrace_set_filter(ops, null_mut(), 0, 0);
        }
```


the `bpf_dispatcher_xdp_func_cb` ftrace callback is also mostly a 1:1 port of the C callback, with the added logic for loading the `XDP_HOOK` pointer (and since `ftrace_regs_set_instruction_pointer` is a tiny macro I just expanded it by hand rather than defining a wrapper in a separate `.c` file, but yes, this isn't portable):

```
    unsafe extern "C" fn bpf_dispatcher_xdp_func_cb(
        _ip: c_ulong,
        _parent_ip: c_ulong,
        _op: *mut ftrace_ops,
        fregs: *mut ftrace_regs,
    ) {
        let hook_ptr = XDP_HOOK.load(SeqCst);
        if hook_ptr.is_null() {
            return;
        }

        unsafe {
            let fregs = fregs as *mut __arch_ftrace_regs;
            (*fregs).regs.ip = hook_ptr as usize as c_ulong;
        }
    }
```

then a simple Rust module implementation to wire everything together:

```
impl kernel::Module for XdpFtrace {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        Self::install_hook(Self::xdp_force_pass)?;
        Ok(XdpFtrace)
    }
}

impl Drop for XdpFtrace {
    fn drop(&mut self) {
        Self::unregister();
    }
}
```

and finally the actual hook, the reason for all of this: the arbitrary logic that we want to run in XDP without asking the verifier for permission.

In this case, just to show everything is working, we overwrite the loaded eBPF program (which drops all traffic) with something that constantly returns `XDP_PASS`:

```
impl XdpFtrace {
    unsafe extern "C" fn xdp_force_pass(_: *const c_void, _: *const bpf_insn, _: bpf_func_t) -> u32 {
        xdp_action_XDP_PASS as u32
    }
}
```

Let's add the last few missing bindings to the Makefile:

```
	--allowlist-type 'xdp_buff' \
	--allowlist-type 'bpf_func_t' \
	--allowlist-type 'xdp_action' \
	--allowlist-var 'XDP_.*' \
	--allowlist-var 'xdp_action_.*' \
```

and after building and loading the Rust module, we should see (if we have `enable-xdp` loading an `XDP_DROP` program) that traffic goes back to flowing:

```
From 192.168.1.120 icmp_seq=4 Destination Host Unreachable
From 192.168.1.120 icmp_seq=5 Destination Host Unreachable
64 bytes from 192.168.1.1: icmp_seq=11 ttl=64 time=1.13 ms
64 bytes from 192.168.1.1: icmp_seq=12 ttl=64 time=1.45 ms
```


## What about dev_xdp_install

ftrace was fun, but as I mentioned it requires _enabling_ XDP first. That means loading a dummy BPF program and going through the verifier just to put the NIC in XDP mode, even though the eBPF program never actually runs (as we replace it with our own function).

Now that we know how to build a Rust LKM and deal with missing bindings, it should be easy (tm) to do this without a dummy program or dispatcher live patch. The idea is to keep everything self contained in a single module and call `dev_xdp_install()` directly (the same function used by netlink / `BPF_LINK_CREATE`) but with our own `bpf_prog` and a `bpf_func` pointer that points to our code.

Since the reader is now an expert on running Rust LKM modules/bindings etc., I'll keep this part shorter.

At a high level we need to:

* Grab a reference to the NIC with `dev_get_by_index()`
* Resolve `dev_xdp_install` (and in generic mode also `generic_xdp_install`) with a ~small hack~ kprobe symbol lookup, since they're `static`/not exported
* Figure out the correct `bpf_ndo` function for our NIC (depending also on the `SKB` or `DRV` mode)
* Allocate a minimal `struct bpf_prog` and point `bpf_func` to our hook
* Wire everything together by calling `dev_xdp_install()`
* Keep an eye on three different kinds of locks/refcounts that need to be released when something fails or on detach

So here's a stripped-down version without `DRV` mode, detach logic, and a couple of other details (full version [here](https://github.com/jibi/xdp-rust-lkm/blob/master/dev_xdp_install/dev_xdp_install_main.rs)):

```
fn lookup_sym(name: *const c_char) -> *mut c_void {
    let mut addr: *mut c_void = null_mut();

    let mut kp: kprobe = unsafe { mem::zeroed() };
    kp.symbol_name = name as *const c_char;

    if unsafe { register_kprobe(&mut kp) == 0 } {
        addr = kp.addr as *mut c_void;
        unsafe { unregister_kprobe(&mut kp) };
    }

    addr
}

impl DevXdpInstall {
    fn get_dev(ifindex: i32) -> Result<*mut net_device> {
        let dev = unsafe { dev_get_by_index(&raw mut init_net, ifindex) };
        if dev.is_null() {
            return Err(ENODEV);
        }

        Ok(dev)
    }

    fn get_bpf_op(dev: *mut net_device) -> Result<BpfOpFn> {
        let sym = lookup_sym(b"generic_xdp_install\0".as_ptr() as *const c_char);
        if sym.is_null() {
            return Err(Error::from_errno(-(ENOSYS as i32)));
        }

        Ok(unsafe { mem::transmute(sym) })
    }

    fn get_dev_xdp_install() -> Result<DevXdpInstallFn> {
        let sym = lookup_sym(b"dev_xdp_install\0".as_ptr() as *const c_char);
        if sym.is_null() {
            return Err(Error::from_errno(-(ENOSYS as i32)));
        }

        Ok(unsafe { mem::transmute(sym) })
    }

    fn alloc_prog(&mut self) -> Result<()> {
        let bpf_prog = unsafe { bpf_prog_alloc(mem::size_of::<bpf_prog>() as u32, 0) };
        if bpf_prog.is_null() {
            return Err(ENOMEM);
        }

        unsafe { 
            bpf_prog_add(bpf_prog, 1);
..
            (*bpf_prog).bpf_func = self.xdp_fn;
        }

        self.bpf_prog = bpf_prog;
        Ok(())
    }

    fn do_dev_xdp_install(&mut self, attach: bool) -> Result<()> {
        let mode = ..
        let flags = ..

        let err = unsafe {
            (self.dev_xdp_install)(self.dev, mode, self.bpf_op, null_mut(), flags, self.bpf_prog)
        };
        if err != 0 {
            return Err(Error::from_errno(err));
        }

        Ok(())
    }

    fn attach_xdp(&mut self) -> Result<()> {
        self.alloc_prog().inspect_err(|_| {
            unsafe { netdevice_dev_put(self.dev) };
        })?;

        self.do_dev_xdp_install(true).inspect_err(|_| {
            unsafe { netdevice_dev_put(self.dev) };
            unsafe { bpf_prog_put(self.bpf_prog) };
        })?;

        Ok(())
    }
}

impl kernel::Module for DevXdpInstall {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let _rtnl = RtnlGuard::lock();

        let ifindex = *module_parameters::ifindex.value();

        let dev = Self::get_dev(ifindex)?;

        let dev_xdp_install = Self::get_dev_xdp_install().inspect_err(|_| {
            unsafe { netdevice_dev_put(dev) };
        })?;

        let bpf_op = Self::get_bpf_op(dev).inspect_err(|_| {
            unsafe { netdevice_dev_put(dev) };
        })?;

        let mut state = DevXdpInstall {
            dev,
            dev_xdp_install,
            bpf_op,
            xdp_fn: Some(xdp_fn),
            bpf_prog: null_mut(),
        };

        state.attach_xdp()?;

        Ok(state)
    }
}
```

This time we can test it in the opposite way: make the module install a function that always drops traffic, and after loading it we should see no more traffic flowing in.

## Fun with the verifier

This write up was mostly about the _ability_ to run arbitrary code in the XDP path. Goal achieved, fun over. But we can't party all the time, so before wrapping it up, let's show some _value_.

Here's one example of something we cannot run in XDP with eBPF (or at least, not without expressing it differently, constraining it, or forcing it to use helpers).

The snippet below scans a packet, looks for the `0xcafecafe` bytes, and if it finds them it returns `XDP_DROP` to drop the packet. It's based on [aya-rs](https://github.com/aya-rs/aya), so we can build our eBPF program in Rust (hence the slightly different function signature):

```
#[xdp]
pub fn test(ctx: XdpContext) -> u32 {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    let packet_len = (data_end as usize) - (data as usize);

    for offset in 0..packet_len.saturating_sub(4-1) {
        if unsafe { core::ptr::read_unaligned(data.add(offset) as *const u32) } == 0xcafecafe {
            return xdp_action::XDP_DROP;
        }
    }

    xdp_action::XDP_PASS
}
```


There's probably nothing too contentious about this example (besides its actual utility) but if we load it, the verifier will complain with what's likely the most common error message for anyone getting started with eBPF:

```
invalid access to packet, off=0 size=4, R5(id=0,off=0,r=0)
R5 offset is outside of the packet
```

Here the verifier is trying to ensure, as part of its safety checks, that our program won't read/write outside the bounds of the packet. Allowing arbitrary kernel reads/writes would be bad, as that could panic the kernel, trigger page faults in softirq context, leak kernel memory to unprivileged userspace programs through maps, allow privilege escalation etc.

The error may sound confusing as our logic appears fine, so why can't the verifier prove that the access to the packet is safe? The catch is `packet_len`: once we turn `data_end - data` into a scalar, the verifier loses the direct relationship between `data` and `data_end`, so it can't conclude that `data + offset + 4 <= data_end`.

The only thing it can recognize is an explicit pointer to pointer bounds check:

```
    if (data + offset + len > data_end)
        return ...

    // access up to data + offset + len
```

To make sense of that, we need to look at how the [verifier](https://elixir.bootlin.com/linux/v6.19/source/kernel/bpf/verifier.c) works:

* As part of its various checks, the verifier goes through all instructions
* When inspecting a conditional jump, it calls `check_cond_jmp_op()`, which among other things calls `try_match_pkt_pointers()`
* That tries to recognize a packet bounds comparison by checking the `type` metadata of the two registers used by the conditional jump: one must be `PTR_TO_PACKET` (a packet pointer with tracked offset/range metadata, i.e. not necessarily the original `ctx->data`) and the other `PTR_TO_PACKET_END`. Which one is src/dst depends on the jump opcode
* Then `find_good_pkt_pointers()` is called on the successful branch to update `reg->range` to track how many bytes from `PTR_TO_PACKET` are safe to access while `mark_pkt_end()` gets called on the other branch to close the range
* Next, when there's an actual packet access, `check_mem_access()` -> `check_packet_access()` will enforce that the access stays within `reg->range`, otherwise the program is rejected

So if we add an explicit pointer bounds check:

```
    for offset in 0.. {
        if unsafe { data.add(offset + 4) } > data_end {
            break;
        }

        if unsafe { core::ptr::read_unaligned(data.add(offset) as *const u32) } == 0xcafecafe {
            return xdp_action::XDP_DROP;
        }
    }
```

the verifier will be happy about packet boundaries and we can move on to...

the next error :D (probably more interesting):

```
The sequence of 8193 jumps is too complex.
```

This time this isn't about memory safety but rather termination. As a matter of fact, the verifier has to prove that the program converges: every possible execution path must eventually reach an `exit` instruction (hint: loops are where that gets tricky).

To prove termination, the verifier does a DFS over all possible execution paths and tracks a state (registers, stack slots, packet bounds, etc.) per instruction. When it hits a conditional jump it can't resolve, it explores one branch and calls `push_stack()` on the other to save it on the DFS stack. Then, when it reaches an `exit` instruction, it pops the next state from the stack and resumes its visit from there.

In (CS) theory, deciding whether arbitrary code halts is undecidable (:wave: halting problem), so the verifier has to be conservative and rely on heuristics and hard limits (like the 1M instructions or the 8k jump sequence limits) that show up as constraints we need to follow when writing eBPF.

If we look at the bytecode that's being rejected:

```
➜  aya-test llvm-objdump -S --no-show-raw-insn $(find | rg 'target/.*/out/test$') | rg -v ';'
..
       0:	w2 = *(u32 *)(r1 + 0x4)
       1:	w1 = *(u32 *)(r1 + 0x0)
       2:	r1 += 0x4
       3:	r3 = 0xcafecafe ll
       5:	r0 = 0x2
       6:	if r1 > r2 goto +0x4 <test+0x58>
       7:	r0 = 0x1
       8:	w4 = *(u32 *)(r1 - 0x4)
       9:	r1 += 0x1
      10:	if r4 != r3 goto -0x6 <test+0x28>
      11:	exit
```

and the related execution flow:

```
┌───────────────────────────┐       
│ 0: w2 = *(u32 *)(r1 + 0x4)│       
│ 1: w1 = *(u32 *)(r1 + 0x0)│       
│ 2: r1 += 0x4              │       
│ 3: r3 = 0xcafecafe ll     │       
│ 5: r0 = 0x2               ◄──────┐
│ 6: if r1 > r2 goto +0x4   │      │
└┬──┬───────────────────────┘      │
 T  F                              │
 │  │                              │
 │ ┌▼──────────────────────────┐   │
 │ │ 7: r0 = 0x1               │   │
 │ │ 8: w4 = *(u32 *)(r1 - 0x4)│   │
 │ │ 9: r1 += 0x1              │   │
 │ │10: if r4 != r3 goto -0x6  ├─T─┘
 │ └┬──────────────────────────┘    
 │  F                               
 │  │                               
┌▼──▼───────────────────────┐       
│11: exit                   │       
└───────────────────────────┘
```

We can see two conditional jumps: the bounds guard we just added (6), and the back edge that brings us back to the beginning of the loop when the `0xcafecafe` match fails (10). The latter is what triggers the verifier failure, as the verifier can't assume anything about packet contents, and it also can't prove that reaching instruction 5 again is equivalent to a previously visited state as `r1` keeps advancing and `r4` depends on unknown packet data.

So pruning (i.e. skipping visiting a state that the verifier considers equivalent to one already visited) doesn't kick in, and the DFS keeps exploring more and more iterations of the loop, each time pushing the fallthrough branch to the stack, until it hits the jump sequence limit, which is why we get the 8193 error.

High level, the visit looks something like:

* visit 0..6
* push the fallthrough case (7) and take the exit branch (11)
* reach `exit`, pop 7
* visit 7..10
* push the fallthrough (11), take the back edge (5)
* repeat until the jump sequence limit is hit

Now that we know exactly what's triggering the failure, we can look for workarounds. For example we can put a hard cap on the number of iterations:

```
    for offset in 0..1500 {
        if unsafe { data.add(offset + 4) } > data_end {
            break;
        }
        if unsafe { core::ptr::read_unaligned(data.add(offset) as *const u32) } == 0xcafecafe {
            return xdp_action::XDP_DROP;
        }
    }
```

This works, but it's not as nice as iterating on the actual packet length as we're guessing a maximum. `1500` is a reasonable MTU-ish cap, but it also means we'll stop scanning early on larger frames.

And we can't just set it to something huge either. Even with a hard upper bound, each extra iteration forces the verifier to explore at least one more unresolved branch (match vs no-match), and eventually we hit `BPF_COMPLEXITY_LIMIT_JMP_SEQ` (8192). For example `0..8192` still trips the verifier:

```
The sequence of 8193 jumps is too complex.
```

We can look into splitting (strip-mining) the loop into smaller chunks:

```
const CHUNK_SIZE: usize = 5000;
const CHUNKS: usize = 2;

#[xdp]
pub fn test(ctx: XdpContext) -> u32 {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    for chunk in 0..CHUNKS {
        for offset in (chunk * CHUNK_SIZE)..((chunk + 1) * CHUNK_SIZE) {
            if unsafe { data.add(offset + 4) } > data_end {
                return xdp_action::XDP_PASS;
            }

            if unsafe { core::ptr::read_unaligned(data.add(offset) as *const u32) } == 0xcafecafe {
                return xdp_action::XDP_DROP;
            }
        }
    }

    xdp_action::XDP_PASS
}
```

this also works, but we lose a bit in readability.

Alternatively we can use the `bpf_loop()` helper:

```
#[repr(C)]
struct LoopCtx {
    data: *const u8,
    data_end: *const u8,
    found: u32,
}

unsafe extern "C" fn scan_cb(index: u32, ctx: *mut c_void) -> c_long {
    let ctx = unsafe { &mut *(ctx as *mut LoopCtx) };
    let data = ctx.data as *const u8;
    let data_end = ctx.data_end as *const u8;
    let offset = (index & 0x7FFF) as usize;

    if unsafe { data.add(offset + 4) } > data_end {
        return 1;
    }

    if unsafe { core::ptr::read_unaligned(data.add(offset) as *const u32) } == 0xcafecafe {
        ctx.found = 1;
        return 1;
    }

    0
}
..
    let mut loop_ctx = LoopCtx {
        data,
        data_end,
        found: 0,
    };

    unsafe {
        bpf_loop(
            packet_len as u32,
            scan_cb as *mut c_void,
            &mut loop_ctx as *mut _ as *mut c_void,
            0,
        );
    }
```

that also works, but we end up with a lot of callback and related context boilerplate just to run a loop.

So pick your poison: raw/chunked loops with hard limits, `bpf_loop()`s (~batteries~ boilerplate included), or the Rust LKM hook 'n' pray hack.

## Other terrible ideas and closing words

The previous example was mostly about a verifier failure and the tradeoffs/workarounds it forces. But excluding eBPF from the equation isn't just about the verifier. It means we can enjoy other terrible practices: call kernel functions we are not supposed to, even `static` ones we are _really, really_ not supposed to (yes, there are eBPF `kfuncs`, but those are much more limited), or allocate kernel memory dynamically (only `GFP_ATOMIC` though, remember we are in softirq/BH context), or implement our own mechanism to share data with userspace, just for fun.

Do we _really_ need all this flexibility? I'll leave that to you.

I'm not taking sides as this was mostly an excuse to play with Rust LKMs, you can either have portable, safe kernel code that runs on pretty much every Linux version without even recompiling the bytecode, or more efficient/readable/boilerplate-free logic that can do many more things, including panicking your kernel.

Anyway, fun is over for real now. Hopefully writing Rust LKMs feels a bit less arcane!

## The picture

![Dolomites](dolomites.png)

View of the Rosengarten (Catinaccio) group in the Dolomites from the Lungotalvera promenade in Bolzano (Bozen). 10/10 chill writing spot, would recommend for extra inspiration.
