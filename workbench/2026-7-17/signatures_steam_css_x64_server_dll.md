================================================================================
server.dll (64-bit) — UTIL_BloodDrips & UTIL_BloodSpray 逆向分析
================================================================================

| 项目       | 说明                                                     |
|------------|----------------------------------------------------------|
| 目标文件   | `server.dll`                                             |
| ImageBase  | `0x180000000`                                            |
| MD5        | `cd5bc8d252fcc917852a93916b3f8ca0`                       |
| 架构       | x86-64 (AMD64)                                           |
| PE时间戳   | 2025-02-17                                               |
| 源参考     | `FJH03/source-engine` (2018 TF2 泄露, nillerusr 修改版)   |
| 工具       | `ida-pro-mcp` (idalib headless)                          |
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
| 源码   | `game/server/effects.cpp:1152`    |
| 功能   | 发送 bloodspray 特效到客户端; 检查 DONT_BLEED, 调用 DispatchEffect |

```cpp
// 等效源码
void UTIL_BloodSpray( const Vector &pos, const Vector &dir, int color, int amount, int flags )
{
    if ( color == DONT_BLEED )
        return;
    CEffectData data;
    data.m_vOrigin = pos;
    data.m_vNormal = dir;
    data.m_flScale = (float)amount;
    data.m_fFlags = flags;
    data.m_nColor = color;
    DispatchEffect( "bloodspray", data );
}
```

**IDA 签名:**
```
41 83 F8 FF 0F 84 ? ? ? ? 55 48 8D 6C 24 B1 48 81 EC B0 00 00 00
```

**x64 (x64dbg/Code) 签名:**
```
\x41\x83\xF8\xFF\x0F\x84\x2A\x2A\x2A\x2A\x55\x48\x8D\x6C\x24\xB1\x48\x81\xEC\xB0\x00\x00\x00
```

**关键特征:**
- `41 83 F8 FF` — `cmp r8d, -1` (DONT_BLEED == -1)
- `55 48 8D 6C 24 B1` — `push rbp; lea rbp, [rsp-0x4F]`
- `48 81 EC B0 00 00 00` — `sub rsp, 0xB0` (CEffectData 栈分配 ~0xB0)


### UTIL_BloodDrips

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_1802BFE80` (size `0x1C5`)    |
| 源码   | `game/shared/util_shared.cpp:775` |
| 功能   | 血液滴溅特效分发; 低暴力模式/德语版检查; BLOOD_COLOR_MECH→火花; 多人模式放大 |

```cpp
// 等效源码
void UTIL_BloodDrips( const Vector &origin, const Vector &direction, int color, int amount )
{
    if ( !UTIL_ShouldShowBlood( color ) ) return;
    if ( color == DONT_BLEED || amount == 0 ) return;
    if ( g_Language.GetInt() == LANGUAGE_GERMAN && color == BLOOD_COLOR_RED ) color = 0;
    if ( g_pGameRules->IsMultiplayer() ) amount *= 5;
    if ( amount > 255 ) amount = 255;
    if ( color == BLOOD_COLOR_MECH ) {
        g_pEffects->Sparks(origin);
        if (random->RandomFloat(0,2) >= 1) UTIL_Smoke(origin, ...);
    } else {
        UTIL_BloodImpact( origin, direction, color, amount );
    }
}
```

**IDA 签名:**
```
41 83 F8 FF 0F 84 ? ? ? ? 48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D 6C 24 A9 48 81 EC C0 00 00 00
```

**x64 (x64dbg/Code) 签名:**
```
\x41\x83\xF8\xFF\x0F\x84\x2A\x2A\x2A\x2A\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x48\x89\x7C\x24\x18\x4C\x89\x74\x24\x20\x55\x48\x8D\x6C\x24\xA9\x48\x81\xEC\xC0\x00\x00\x00
```

**关键特征:**
- `41 83 F8 FF` — `cmp r8d, -1` (DONT_BLEED == -1)
- `48 89 5C 24 08 ... 4C 89 74 24 20` — 保存 rbx, rsi, rdi, r14 (4个非易失寄存器 → 复杂函数)
- `55 48 8D 6C 24 A9` — `push rbp; lea rbp, [rsp-0x57]`
- `48 81 EC C0 00 00 00` — `sub rsp, 0xC0` (大于 UTIL_BloodSpray 的 0xB0，函数更复杂)


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
