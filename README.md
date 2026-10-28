# win16-installer-unpack

一个用于解包 1990 年代 Win16 安装包 / 屏保 / 自解压程序的工具与方法论文档。
针对的场景很具体：**文件尾部有一大段熵接近 7.9 的数据，`binwalk`、`file`、`7-Zip` 全都认不出来，
资源提取器只能掏出几个图标。**

*Recover files embedded in legacy 16-bit Windows executables (NE/LE) — Wise Installation
System, InstallShield 16-bit, and custom self-extractors.*

---

## 它解决什么问题

遇到这种 exe 时，最常见的两个误判是：

1. **以为 exe 就是程序本体。** 1990 年代的软盘里装的往往是一个**安装包**，真正的程序和数据是它内部压缩包里的成员。
2. **以为扫不到签名就是加密了。** 裸 DEFLATE 流（RFC1951）没有 zlib 头、没有 gzip 头、没有尾部校验、没有 magic，
   熵 7.9 bit/byte 且零签名命中是**正常形态**，不是加密证据。

本工具的做法是绕开签名，直接从结构切入：

```
识别打包器  →  用熵边界定位载荷起点  →  按「deflate 流 + CRC32」走完整个 overlay
```

## 快速开始

```bash
# 1. 探测：解析 NE 头、段表、资源表，标出没有被任何结构认领的字节区间，
#    并根据字符串判断打包器
python3 scripts/ne_probe.py target.exe

# 2.（可选）看全部字符串，人工确认打包器
python3 scripts/ne_probe.py target.exe --strings

# 3. 解包：自动定位载荷起点，顺序解压所有成员
python3 scripts/deflate_walk.py target.exe

# 也可以指定偏移，或先只列表不写盘
python3 scripts/deflate_walk.py target.exe --start 0x3e6e
python3 scripts/deflate_walk.py target.exe --list-only
```

产物默认落在 `<exe 所在目录>/unpacked/`，命名为 `NN_<偏移>.<扩展名>`，扩展名由解压后数据的 magic 推断。

### 探测输出示例

```
NE offset       : 0x400  magic=NE  ver=5.60
align shift     : 4   cseg=2  cmod=3  cres=0

segments:
  seg 1 @0x000004d0 size= 199408 CODE reloc=True minalloc=12464
  seg 2 @0x000037c0 size=  14096 DATA reloc=True minalloc=1050

** WARNING: segment table is unreliable (overlapping entries).
   Trust the entropy boundary below, not the segment sizes.

high-entropy run starts at 0x00004000 -> payload candidate

installer / runtime signatures found in low region:
  * Wise Installation System: GLBSInstall, WiseMain, UpdateScreen, DisplayGraphics, DiskPrompt
  * Visual Basic 3 runtime: ___EXPORTEDSTUB
```

### 解包输出示例

```
auto-located start: entropy boundary 0x4000, stream anchored at 0x3e6e

[00] 0x00003e6e comp=   1478 infl=    3129 txt  crc=OK  0400601b000817150000000000000000
[01] 0x00004438 comp=  40077 infl=   71968 exe  crc=OK  4d5a37010200000004000000ffff0000
[03] 0x00010fc8 comp=  21993 infl=   64337 exe  crc=OK  4d5aff000500000020000000ffff0000
[04] 0x000165b5 comp=     86 infl=     880 txt  crc=OK  6631352e6a706720726e642020202020
[05] 0x0001660f comp=  32224 infl=   32275 jpg  crc=OK  ffd8ffe000104a464946000101010048
...
21 members, 1435662 compressed -> 1881033 inflated bytes
```

## 锚定原理

成员在文件里的排布是：

```
[ raw deflate 流 ][ uint32 小端 crc32(解压后数据) ]
```

脚本判定一个偏移是「真实接缝」的条件有三条，缺一不可：

1. 流能**完整**解压（`zlib.decompressobj(-15)` 到达 `eof`）；
2. 解压输出 **≥ 64 字节**；
3. 紧随其后的 4 个字节等于 `crc32(解压数据)`。

第 3 条让误判概率低到可以忽略，同时顺带校验了每一个成员。第 2 条是必须的：
`03 00` 解压出 0 字节，而 `crc32(b"") == 0`，紧跟 `00 00 00 00` 就会「完美通过」——
编译产物里这种空流有几千个，不加输出长度门槛，自动模式会被它带偏。

## 支持范围

| 打包器 | 处理方式 |
|---|---|
| Wise Installation System（16 位） | 直接走 deflate 解包，已验证 |
| InstallShield 3.x（`_isys`） | 走 `unshield` / `i6comp`，不是 deflate |
| LZSS 风格的自解压 stub | 需换 LZSS 解码器，以 CRC 或长度字段锚定 |
| 未知打包器 | 优先尝试 deflate 解包，Cover 率最高 |

仅 **NE** 的头字段会被正确解析。LE（线性可执行，DOS4GW 那一类）只做**签名识别**：
脚本不会报“不是可执行文件”，但头部字段是按 NE 布局读的，在 LE 上会是垃圾值，别信那些数字——
此时只有熵边界检测和 deflate 走查仍然有效。

## 能力边界

这套方法只对**一种**内部结构成立：成员逐条排列，每条是「裸 deflate 流 + 4 字节 CRC32」。
超出这个结构的情况，工具的定位是**给出判据并早点停下**，而不是硬解。

| 情况 | 结果 |
|---|---|
| 成员之间没有 CRC32（只有 `[长度][数据]`） | 只能解出第一个成员，随后因锚点失效而停止 |
| 载荷被真正加密，或换了自定义 LZ / RLE | 完全不适用，需要反汇编解压函数 |
| EXE 自身先被 LZEXE / PKLITE / WWPACK 压过 | 不适用：NE 头是壳的，字符串也露不出打包器名字 |
| 载荷在资源表里（`RT_RCDATA` / `RT_BITMAP`） | 不是本工具的场景；且本仓库的资源表解析在样本上就是失败的 |
| Wise 32 位（带 `WIS` 头、多碟、`FILE00XX.DAT`） | 未实现头的语义解析；流能取出，但命名与归属需人工判断 |
| 需要解释运行时行为（读哪些文件、写哪注册表） | 超出范围，本工具不做反汇编 |

还有两条实现层面的限制值得知道：

- **首个成员若压缩后超过约 128 KB，自动定位可能漏掉它**（锚点探测只喂前 128 KB 输入）。
  已知真值偏移时用 `--start` 绕开。
- **大文件且熵特征不明显时会很慢**。自动定位的最后兜底是全文件逐字节试探，
  10 MB 以上基本不可接受；解压后的 BMP 之类低熵载荷就属于这种情况，请直接给 `--start`。

## 真实文件名从哪来

解出来的成员是按偏移命名的，真实名字通常就在压缩包里，有两处：

- **名表成员**：常在载荷靠前位置，定长记录（80 字节很常见：`NAME.EXT` + 类型字 + NUL 填充）。
- **安装脚本**：本身就是压缩包的第一个成员，Wise 的通常是 1–4 KB 明文，内容形如
  `%WIN%\APPNAME.SCR`、`%SYS%\VBRUN300.DLL`，能直接拿到安装清单和目标目录。

两者冲突时以安装脚本为准——它记录的是安装器**实际做过什么**。

## 案例

`references/ne-format.md` 里有一个完整案例：1997 年麦克唐纳-道格拉斯公司发行的飞机屏保，
1.4 MB 的 NE 安装包，21 个成员，11 张 640×480 JPEG，全自动解包耗时 0.35 秒。
文档里同时列出了当时被推翻的几个错误结论（「加密了」「在资源表里」「自定义压缩」）及其原因。

## 已知陷阱

- **空 deflate 流**会伪装成有效锚点，见上文「锚定原理」。
- **段表不可信**：安装器 stub 的段表经常自相重叠或超出文件长度，别用它推载荷起点，用熵边界。
- **不要按 `xxd` 的两字节命中切片**（`0a05`、`ffd8`、`424d`）：随机数据每 64 KB 左右就会撞一次。
- **16 位反汇编对解包是多余的**，只在需要解释运行时行为（读哪些文件、写什么注册表）时才需要。
- **CRC 不匹配 = 边界错了**，不是数据坏了。不要跳过校验。

## 安装为 WorkBuddy Skill

本仓库目录结构就是一个标准 skill（`SKILL.md` + `scripts/` + `references/`）。整目录放进
`~/.workbuddy/skills/win16-installer-unpack/` 即可，工具链在对话里会自动按需加载。

## 许可

MIT，见 [LICENSE](LICENSE)。

仅用于对合法持有的旧软件做格式研究与数据恢复。解包产物（图像、程序、商标）的权利仍归原权利人所有。
