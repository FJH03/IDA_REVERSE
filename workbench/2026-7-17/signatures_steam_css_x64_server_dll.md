================================================================================
server.dll (64-bit) — UTIL_BloodDrips & UTIL_BloodSpray 逆向分析
================================================================================

| 项目       | 说明                                                     |
|------------|----------------------------------------------------------|
| 目标文件   | `library/css_steam/v93/x64/server.dll`                   |
| ImageBase  | `0x180000000`                                            |
| MD5        | `cd5bc8d252fcc917852a93916b3f8ca0`                       |
| 架构       | x86-64 (AMD64)                                           |
| PE时间戳   | 2025-02-17                                               |
| 源参考     | `FJH03/source-engine` (2018 TF2 泄露, nillerusr 修改版)   |
| 签名工具   | `makesig.idc` (IDA 脚本: wildcard 跳转 + FIXUP 重定位)    |
| 分析工具   | `ida-pro-mcp` (idalib headless)                          |
| 日期       | 2026-07-17                                               |


---

## 定位方法论

### UTIL_BloodSpray

```
源码 (game/server/effects.cpp:1145):
  void UTIL_BloodSpray(pos, dir, color, amount, flags)
    → if (color == DONT_BLEED) return;
    → DispatchEffect("bloodspray", data)

追索链:
  搜字符串 "bloodspray" → 3处命中
    → 0x18000D7A3: ConCommand 注册 (CC_BloodSpray)
    → 0x18017FFA9: CC_BloodSpray 函数内联调用 UTIL_BloodSpray
    → 0x180181EEC: sub_180181EB0 直接调用 DispatchEffect("bloodspray")
      → 反编译确认: cmp r8d,-1 (DONT_BLEED); CEffectData 结构填充; DispatchEffect 调用
      → 交叉验证: CBlood::InputEmitBlood (sub_180180A60) 调用它, 传 flags 参数
```

### UTIL_BloodDrips

```
源码 (game/shared/util_shared.cpp:775):
  void UTIL_BloodDrips(origin, direction, color, amount)
    → UTIL_ShouldShowBlood → DONT_BLEED/LANGUAGE_GERMAN/IsMultiplayer 检查
    → color==BLOOD_COLOR_MECH → Sparks/Smoke
    → else → DispatchEffect("bloodimpact", data)

追索链:
  搜字符串 "bloodimpact" → 4处命中
    → 0x1802BFF81: sub_1802BFE80 调用 DispatchEffect("bloodimpact")
      → 反编译确认: cmp r8d,-1; IsMultiplayer() vcall; amount*=5; color==3→Sparks/Smoke
      → 交叉验证: CBlood::InputEmitBlood 在非 STREAM 分支调用它
```


---

## 签名

### UTIL_BloodSpray

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_180181EB0` (size `0xD1`)     |
| 地址   | `0x180181EB0`                     |
| 源码   | `game/server/effects.cpp:1152`    |
| 功能   | 发送 bloodspray 特效到客户端; 检查 DONT_BLEED, 调用 DispatchEffect |

#### 唯一签名 (makesig.idc 生成)

```
IDA : 41 83 F8 FF 0F 84 ? ? ? ? 55
x64 : \x41\x83\xF8\xFF\x0F\x84\x2A\x2A\x2A\x2A\x55
```

#### 反编译代码 (Hex-Rays)

```cpp
// 调用约定: __fastcall (x64)
//   rcx = pos (Vector*)
//   rdx = dir (Vector*)
//   r8d = color
//   r9d = amount
//   [rsp+0x28] = flags
__int64 __fastcall sub_180181EB0(
    _DWORD *a1,    // pos (Vector*)
    int *a2,        // dir (Vector*)
    int a3,         // color
    int a4,         // amount
    int a5)         // flags
{
    _DWORD v8[3];   // CEffectData.m_vOrigin  [rsp+20h]
    // ... (其余字段为 CEffectData 零初始化)
    float v18;      // CEffectData.m_flScale   [rsp+58h]
    int v16;        // CEffectData.m_fFlags    [rsp+50h]
    char v24;       // CEffectData.m_nColor    [rsp+78h]

    // ── 1. DONT_BLEED 检查 ──
    if ( a3 != -1 )              // if (color != DONT_BLEED)
    {
        // ── 2. 填充 CEffectData ──
        v8[0] = *a1;             // data.m_vOrigin.x = pos.x
        v8[1] = a1[1];           // data.m_vOrigin.y = pos.y
        v8[2] = a1[2];           // data.m_vOrigin.z = pos.z

        v11 = *a2;               // data.m_vNormal.x = dir.x
        v12 = a2[1];             // data.m_vNormal.y = dir.y
        v13 = a2[2];             // data.m_vNormal.z = dir.z

        v18 = (float)a4;         // data.m_flScale = (float)amount
        v16 = a5;                // data.m_fFlags  = flags
        v24 = a3;                // data.m_nColor  = color

        // ── 3. 发送特效 ──
        return sub_1803F27C0(    // DispatchEffect("bloodspray", &data)
            "bloodspray",
            v8);
    }
    return result;               // color == DONT_BLEED → 直接返回
}
```

> **注:** `CEffectData` 结构体约 0xB0 字节，反编译中的大量 `vXX = 0` 是 Release 编译器的结构体零初始化被展开。

#### 等效源码

```cpp
// game/server/effects.cpp:1152
void UTIL_BloodSpray( const Vector &pos, const Vector &dir,
                      int color, int amount, int flags )
{
    if ( color == DONT_BLEED )  // DONT_BLEED = -1
        return;

    CEffectData data;
    data.m_vOrigin = pos;
    data.m_vNormal = dir;
    data.m_flScale = (float)amount;
    data.m_fFlags  = flags;
    data.m_nColor  = color;

    DispatchEffect( "bloodspray", data );
}
```


### UTIL_BloodDrips

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_1802BFE80` (size `0x1C5`)    |
| 地址   | `0x1802BFE80`                     |
| 源码   | `game/shared/util_shared.cpp:775` |
| 功能   | 血液滴溅特效分发; 低暴力模式/德语版检查; BLOOD_COLOR_MECH→火花; 多人模式放大 |

#### 唯一签名 (makesig.idc 生成)

```
IDA : 41 83 F8 FF 0F 84 ? ? ? ? 48 89 5C 24 08
x64 : \x41\x83\xF8\xFF\x0F\x84\x2A\x2A\x2A\x2A\x48\x89\x5C\x24\x08
```

#### 反编译代码 (Hex-Rays)

```cpp
// 调用约定: __fastcall (x64)
//   rcx = origin (Vector*)
//   rdx = dir (Vector*)
//   r8d = color
//   r9d = amount
void __fastcall sub_1802BFE80(
    _DWORD *a1,    // origin (Vector*)
    int *a2,        // dir (Vector*)
    int a3,         // color
    int a4)         // amount
{
    int v5;         // ebx — amount (处理后)

    // ── 1. DONT_BLEED 检查 ──
    if ( a3 != -1 )                           // if (color != DONT_BLEED)
    {
        // ── 2. UTIL_ShouldShowBlood ──
        v4 = qword_1807A8488;                 // g_Language (默认)
        v5 = a4;                              // ebx = amount
        if ( a3 )                             // color != 0 → 另一种语言对象
            v4 = qword_1807A85A8;
        if ( !*(_DWORD *)(v4 + 88) || !a4 )   // !ShouldShowBlood || amount==0
            return;                           // → 直接返回

        // ── 3. IsMultiplayer → amount *= 5 ──
        if ( (*(vtable+272))(qword_180753DD8) ) // g_pGameRules->IsMultiplayer()
            v5 *= 5;                          // amount *= 5

        // ── 4. clamp amount ──
        if ( v5 > 255 )
            v5 = 255;

        // ── 5. BLOOD_COLOR_MECH 分支 ──
        if ( a3 == 3 )                        // BLOOD_COLOR_MECH = 3
        {
            // Sparks(origin)
            ((*off_18067C010)[3])(             // g_pEffects->Sparks(origin)
                off_18067C010, a1, 1);

            // 50% 概率 → UTIL_Smoke
            if ( (*(vtable+8))(qword_1807527D8) >= 1.0 ) // RandomFloat(0,2) >= 1.0
            {
                (*(vtable+16))(qword_1807527D8, 10, 15); // RandomInt(10,15)
                sub_1802BE930(a1);            // UTIL_Smoke(origin, rnd, 10)
            }
        }
        // ── 6. else: UTIL_BloodImpact ──
        else
        {
            _DWORD v11[3];                    // CEffectData
            // ... 填充 m_vOrigin, m_vNormal, m_flScale, m_nColor ...
            v20 = (float)v5;                  // data.m_flScale = (float)amount
            v26 = a3;                         // data.m_nColor  = color

            sub_1803F27C0(                    // DispatchEffect("bloodimpact", &data)
                "bloodimpact",
                v11);
        }
    }
}
```

> **注:** 反编译中大量的 `vXX = 0` 已省略，均为 `CEffectData` 结构体零初始化。

#### 等效源码

```cpp
// game/shared/util_shared.cpp:775
void UTIL_BloodDrips( const Vector &origin, const Vector &direction,
                      int color, int amount )
{
    if ( !UTIL_ShouldShowBlood( color ) )
        return;

    if ( color == DONT_BLEED || amount == 0 )
        return;

    if ( g_Language.GetInt() == LANGUAGE_GERMAN && color == BLOOD_COLOR_RED )
        color = 0;

    if ( g_pGameRules->IsMultiplayer() )
        amount *= 5;                    // 多人模式放大5倍

    if ( amount > 255 )
        amount = 255;

    if ( color == BLOOD_COLOR_MECH )    // BLOOD_COLOR_MECH = 3
    {
        g_pEffects->Sparks( origin );
        if ( random->RandomFloat( 0, 2 ) >= 1.0f )
            UTIL_Smoke( origin, random->RandomInt( 10, 15 ), 10 );
    }
    else
    {
        // 普通血液 → DispatchEffect("bloodimpact", data)
        UTIL_BloodImpact( origin, direction, color, amount );
    }
}
```


---

## 区分要点

两个函数都以 `41 83 F8 FF 0F 84 ?? ?? ?? ??` 开头（都检查 DONT_BLEED），区分方法：

| 特征               | UTIL_BloodSpray                      | UTIL_BloodDrips                      |
|--------------------|---------------------------------------|--------------------------------------|
| 跳过后第一条指令   | `55` (push rbp)                       | `48 89 5C 24 08` (mov [rsp+8], rbx)  |
| 栈帧大小           | `sub rsp, 0xB0`                       | `sub rsp, 0xC0`                      |
| 保存寄存器数       | 1 (rbp)                               | 5 (rbx, rsi, rdi, r14, rbp)          |
| DispatchEffect 参数| `"bloodspray"`                        | `"bloodimpact"` (via UTIL_BloodImpact)|
| 参数个数           | 5 (pos, dir, color, amount, flags)    | 4 (origin, dir, color, amount)       |
| 函数大小           | 0xD1                                  | 0x1C5                                |


---

## 签名生成对比: MCP vs makesig.idc

两个工具生成唯一签名的策略不同：

| 维度 | `make_signature_for_function` (MCP) | `makesig.idc` |
|------|--------------------------------------|----------------|
| 通配范围 | 仅相对跳转/调用位移 | 跳转位移 + FIXUP_OFF32 重定位 |
| 停止粒度 | **字节级** — 可在指令中间停止 | **指令级** — 必须读完完整指令才检查唯一性 |
| UTIL_BloodSpray | `41 83 F8 FF 0F 84 ? ? ? ? 55` | `41 83 F8 FF 0F 84 ? ? ? ? 55` |
| UTIL_BloodDrips | `41 83 F8 FF 0F 84 ? ? ? ? 48 89 5C 24` | `41 83 F8 FF 0F 84 ? ? ? ? 48 89 5C 24 08` |

**UTIL_BloodDrips 差异原因:** `mov [rsp+8], rbx` 是 5 字节指令 (`48 89 5C 24 08`)。MCP 在第 3 字节 (`24`) 处已判定唯一、直接停止；IDC 要求读完完整指令（5 字节全读），所以多了 `08`。

两种签名在实战中均能唯一匹配目标函数。推荐使用 **IDC 版本**（指令原子性更好，与 x64dbg SigMaker 逻辑一致）。


---

## 调用关系

```
CBlood::InputEmitBlood (sub_180180A60)
  ├── SF_BLOOD_STREAM (0x02) → UTIL_BloodStream (sub_1802BBC70)
  ├── else                 → UTIL_BloodDrips  (sub_1802BFE80) ★
  ├── SF_BLOOD_DECAL (0x08)→ UTIL_BloodDecalTrace
  └── SF_BLOOD_CLOUD|DROPS|GORE (0x70) → UTIL_BloodSpray (sub_180181EB0) ★

CC_BloodSpray (sub_18017FED0) — 控制台命令
  └── 循环每个实体 → UTIL_BloodSpray (内联)
```

================================================================================
EOF
