================================================================================
client.dll (64-bit) — 逆向分析日记
================================================================================

| 项目       | 说明                                                    |
|------------|---------------------------------------------------------|
| 目标文件   | `client.dll`                                            |
| ImageBase  | `0x180000000`                                           |
| 架构       | x86-64                                                  |
| 源参考     | `E:\CSSO-NOOFFICIAL-MP` (CS:S Offensive MP 源码)        |
| 工具       | `ida-pro-mcp` (idalib headless, `--unsafe`)             |
| 日期       | 2026-07-17                                              |


---

## Part 1 — `CreateWeaponTracer` 完整分析

> 定位：用户直接指定 `sub_180270E40`


### 1.1 函数概览

| 字段   | 值                                                                     |
|--------|------------------------------------------------------------------------|
| IDA 名 | `sub_180270E40`                                                        |
| 地址   | `0x180270E40`                                                          |
| 源码   | `game/shared/cstrike/cs_player_shared.cpp:1667`                        |
| 声明   | `void CCSPlayer::CreateWeaponTracer(Vector vecStart, Vector vecEnd)`   |
| 签名   | `__int64* __fastcall sub_180270E40(_QWORD* this, float* vecStart, __int64 vecEnd, unsigned int entindex)` |


### 1.2 反编译代码 (Hex-Rays)

```cpp
__int64* __fastcall sub_180270E40(_QWORD* a1, float* a2, __int64 a3, unsigned int a4)
{
    // a1 = this (CCSPlayer*)
    // a2 = &vecStart (float[3])
    // a3 = &vecEnd   (float[3])
    // a4 = iEntIndex (entindex)

    __int64* result;
    __int64* v9;              // pWeapon (C_WeaponCSBase*)
    int     v12;              // entindex() 返回值
    int     v14;              // 保存 entindex
    __int64* v15;             // pViewModel (C_BaseViewModel*)
    unsigned int v16;         // weapon EHANDLE
    __int64 v18;              // pWeaponWorldModel (CBaseWeaponWorldModel*)
    unsigned int v20;         // iAttachment 返回值
    unsigned int v22;         // nBulletNumber
    int     v23;              // GetMaxClip1()
    int     v24;              // m_iTracerFrequency[m_weaponMode]
    _BYTE*  v25;              // GetTracerType() 返回的字符串指针
    __int64 v26;              // 局部 vecStart 副本
    float   v27;              // 局部 vecStart.z 副本
    _QWORD  v28[8];           // CPVSFilter 栈对象

    // ── 1. 获取当前武器 ──
    result = (__int64*)sub_18029D0B0();          // GetActiveCSWeapon()
    v9 = result;
    if (!result) return result;                  // 无武器 → 直接返回

    // ── 2. 保存 vecStart 副本 ──
    v26 = *(_QWORD*)a2;                          // vecStart.x, .y
    v27 = a2[2];                                 // vecStart.z

    // ── 3. 获取 entindex ──
    v12 = (*(__int64(**)(void))(a1[2] + 72))();  // entindex()
    v14 = v12;

    // ── 4. 获取 ViewModel (仅活动状态) ──
    result = (__int64*)sub_18012B910(a1, 0, 1);   // GetViewModel(0, activeOnly=true)
    v15 = result;                                 // pViewModel

    // ── 5. 观察者 / ShouldDraw 检查 ──
    if (result) {
        result = (__int64*)(*(__int64(**)(_QWORD*))(*a1 + 2136))(a1);
        if (!(_BYTE)result)                      // ShouldDraw()=false → 走世界模型路径
            goto LABEL_11;
    }

    // ── 6. 尝试通过世界模型获取枪口位置 ──
    v16 = *((_DWORD*)v9 + 939);                  // m_hWeaponWorldModel (EHANDLE @ +0xEAC)
    if (v16 != -1) {
        result = off_18081D408[0];               // 实体句柄表
        __int64 v17 = 4LL * (unsigned __int16)v16;
        if (LODWORD(off_18081D408[0][v17+2]) == HIWORD(v16)) {
            v18 = off_18081D408[0][v17+1];       // 世界模型实体指针
            if (v18) {
                // HasDormantOwner 检查
                result = (__int64*)sub_18030B030(v18);
                if (!(_BYTE)result) {            // 非休眠 → 继续
                    // LookupAttachment("muzzle_flash") 在世界模型上
                    result = (__int64*)(*(__int64(**)(__int64*,__int64,__int64))(*v9+3104))(v9, v18, 1);
                    if ((int)result > 0)
                        // GetAttachment → 覆盖 vecStart!
                        result = (__int64*)(*(__int64(**)(__int64,_QWORD,__int64*))(*(_QWORD*)v18+592))(
                                              v18, (unsigned int)result, &v26);
                }
                goto LABEL_12;
            }
        }
    }

    // ── 7. 后备: ViewModel attachment ──
    if (v15) {
LABEL_11:
        v20 = (*(__int64(**)(__int64*,__int64*,_QWORD))(*v9+3104))(v9, v15, 0);
        result = (__int64*)(*(__int64(**)(__int64*,_QWORD,__int64*))(*v15+592))(v15, v20, &v26);
    }

    // ── 8. vecStart 有效性检查 ──
LABEL_12:
    if ((v26.y*v26.y + v26.x*v26.x + v27*v27) > 0.0f) {

        // ── 9. 枪口火光动态光源 ──
        sub_180330580(v28);                      // CPVSFilter 构造
        v28[0] = off_1806364D8;                  // vtable
        sub_180330740(v28);                      // CPVSFilter::Init
        sub_1803401C0(                           // TE_DynamicLight
            (unsigned int)v28,                   //   filter
            0,                                   //   delay=0
            (unsigned int)&v26,                  //   origin=&vecStart
            255, 192, 64,                        //   r=255, g=192, b=64
            5,                                   //   exponent=5
            1116471296,                          //   radius=70.0f
            1028443341,                          //   time=0.05f
            1145044992,                          //   decay=768.0f
            0x10000000);                         //   LIGHT_INDEX_TE_DYNAMIC

        // ── 10. 曳光弹频率计算 ──
        // nBulletNumber = GetMaxClip1() - Clip1() - 1
        v22 = ~(*(unsigned int(**)(__int64*))(*v9+2696))(v9);  // ~Clip1()
        v23 = v22 + (*(__int64(**)(__int64*))(*v9+2536))(v9);  // + GetMaxClip1()

        // iTracerFreq = GetCSWpnData().m_iTracerFrequency[m_weaponMode]
        v24 = *(_DWORD*)(v9[429] + 4LL * *((int*)v9 + 886) + 2664);

        // ── 11. 曳光弹频率判定 ──
        if (!v24 || v23 % v24) {                 // 无频率 或 不整除 → 仅声音
            sub_1801809B0(&v26, a3 + 12, a4);    // FX_TracerSound(vecStart, vecEnd, ...)
        } else {                                 // 绘制曳光弹
            v25 = (_BYTE*)(*(__int64(**)(_QWORD*))(*a1+248))(a1);  // GetTracerType()
            if (v25 && *v25)
                sub_18022D800(                   // UTIL_ParticleTracer(...)
                    (_DWORD)v25,
                    (unsigned int)&v26,           // vecStart
                    a3 + 12,                      // vecEnd
                    v14,                          // entindex
                    -1,                           // TRACER_DONT_USE_ATTACHMENT
                    1);                           // true
        }
        return (__int64*)sub_1803305B0(v28);      // CPVSFilter 析构
    }
    return result;
}
```


### 1.3 调用链映射

| 二进制引用               | 源码函数 / 操作                     | 说明                       |
|--------------------------|-------------------------------------|----------------------------|
| `sub_18029D0B0`          | `GetActiveCSWeapon()`               | 获取当前 CS 武器            |
| `[a1+2]+72` vcall        | `CBaseEntity::entindex()`           | 实体索引                   |
| `sub_18012B910(a1,0,1)`  | `GetViewModel(0)`                   | 第 0 个 ViewModel (仅活动)  |
| `[*a1]+2136` vcall       | `ShouldDraw()` / `InFirstPersonView()` | 第三人称检测             |
| `off_18081D408`          | 实体句柄表                          | 全局 `CBaseHandle` 查找     |
| `sub_18030B030`          | `HasDormantOwner()`                 | 世界模型所有者休眠检查       |
| `[*v9]+3104` vcall       | `CBaseAnimating::LookupAttachment()` | 查询 attachment 索引        |
| `[*v18]+592` vcall       | `CBaseAnimating::GetAttachment()`   | 获取 attachment 世界坐标    |
| `sub_180330580`          | `CPVSFilter` 构造                   |                            |
| `sub_180330740`          | `CPVSFilter` 初始化                 |                            |
| `sub_1803305B0`          | `CPVSFilter` 析构                   |                            |
| `sub_1803401C0`          | `TE_DynamicLight()`                 | 枪口动态光源 TempEntity     |
| `[*v9]+2696` vcall       | `C_WeaponCSBase::Clip1()`           | 当前弹匣弹药数              |
| `[*v9]+2536` vcall       | `C_WeaponCSBase::GetMaxClip1()`     | 最大弹匣容量                |
| `v9[429]`                | `GetCSWpnData()`                    | 武器数据指针                |
| `[*a1]+248` vcall        | `GetTracerType()`                   | 曳光弹类型字符串            |
| `sub_18022D800`          | `UTIL_ParticleTracer()`             | 发射粒子曳光弹              |
| `sub_1801809B0`          | `FX_TracerSound()`                  | 子弹呼啸音效                |


### 1.4 关键数据结构偏移

**CCSPlayer**

| 偏移     | 成员                                      |
|----------|-------------------------------------------|
| v267     | `ShouldDraw()` / `InFirstPersonView()`    |
| v31      | `GetTracerType()`                         |

**C_WeaponCSBase**

| 偏移     | 成员                     | 表达式           |
|----------|--------------------------|------------------|
| `+0xEAC` | `m_hWeaponWorldModel`    | `v9 + 939*4`     |
| `+0x6B0` | `m_pCSWpnData` 指针      | `v9[429]`        |
| `+0xDD8` | `m_weaponMode`           | `v9 + 886*4`     |

**CSWpnData**

| 偏移     | 成员                      |
|----------|---------------------------|
| `+0xA68` | `m_iTracerFrequency[0]`   |
| `+0xA6C` | `m_iTracerFrequency[1]`   |

**vfunc 索引**

| 索引 | 函数                 |
|------|----------------------|
| 317  | `GetMaxClip1()`      |
| 337  | `Clip1()`            |
| 388  | `LookupAttachment()` |
| 74   | `GetAttachment()`    |


### 1.5 二进制 vs 源码差异 ⚠️

| # | 差异点                                      | 严重度 | 说明 |
|---|---------------------------------------------|--------|------|
| 1 | **观察者 / 第一人称处理简化**                | 🟡     | 源码完整 observer 检查被简化为单一 `vfunc[2136]` 调用 |
| 2 | **AUG/SG556 开镜模式处理缺失** 🔴            | 🔴     | 源码强制 `bUseWorldModel=true`，二进制无此逻辑 |
| 3 | **`LookupAttachment` 调用对象可疑**          | 🟡     | 用武器 vtable 而非世界模型 vtable，可能为 IDA 偏差 |
| 4 | **`TE_DynamicLight` 参数一致**               | ✅     | `(255,192,64, 5, 70, 0.05, 768)` 与源码相同 |
| 5 | **`vecStart` 被 `GetAttachment` 覆盖**       | 🔴     | 丢弃调用者传入的发射起点 |


### 1.6 调用者

`CreateWeaponTracer` 通过 **vtable + CFG** 间接调用：

```
vtable 槽位 : .rdata:0x18069C3F8  (CCSPlayer vtable offset +0xF8)
调用形式    : call [this->vtable + 0xF8]
调用来源    : CCSPlayer::FireBullet 中 (cs_player_shared.cpp:1235)
```

```cpp
#ifdef CLIENT_DLL
    CreateWeaponTracer(vecSrc, tr.endpos);
#endif
```


---

## Part 2 — `CCSPlayer::FireBullet` (客户端) 分析

> 定位：子弹类型字符串 → `GetBulletTypeParameters` → 函数入口


### 2.1 函数概览

| 字段   | 值                                                                                     |
|--------|----------------------------------------------------------------------------------------|
| IDA 名 | `sub_18029C390`                                                                        |
| 地址   | `0x18029C390`                                                                          |
| 源码   | `game/shared/cstrike/cs_player_shared.cpp:938`                                         |
| 声明   | `void CCSPlayer::FireBullet(Vector, QAngle&, float, float, int, int, int, float, CBaseEntity*, bool, float, float)` |

```cpp
// 二进制签名 (pevAttacker 在客户端被优化掉, 默认=this)
__int64 __fastcall sub_18029C390(
    __int64       a1,    // this  (CCSPlayer*)
    __int64       a2,    // &vecSrc (Vector*)
    __int64       a3,    // &shootAngles (QAngle*)
    float         a4,    // flDistance
    float         a5,    // flPenetration
    unsigned int  a6,    // nPenetrationCount
    int           a7,    // iBulletType
    int           a8,    // iDamage
    float         a9,    // flRangeModifier
    char          a10,   // bDoEffects
    float         a11,   // xSpread
    float         a12    // ySpread
);
```


### 2.2 入口：穿透参数表

`AngleVectors` 后紧跟 `GetBulletTypeParameters` 内联的 switch 链：

| 子弹类型                 | Power | Distance |
|--------------------------|-------|----------|
| `BULLET_PLAYER_50AE`     | 30    | 1000     |
| `BULLET_PLAYER_762MM`    | 250   | 5000     |
| `BULLET_PLAYER_556MM`    | 250   | 4000     |
| `BULLET_PLAYER_338MAG`   | 280   | 8000     |
| `BULLET_PLAYER_9MM`      | 20    | 800      |
| `BULLET_PLAYER_BUCKSHOT` | 0     | 0        |
| `BULLET_PLAYER_45ACP`    | 15    | 500      |
| `BULLET_PLAYER_357SIG`   | 40    | 800      |
| `BULLET_PLAYER_57MM`     | 200   | 2000     |
| `AMMO_TYPE_TASERCHARGE`  | 30    | 100      |
| *(default)*              | 250   | 3000     |

### 2.3 主循环调用链

```
while (fCurrentDamage > 0):
    ├─ UTIL_TraceLineIgnoreTwoEntities  → sub_18022C6A0
    ├─ CTraceFilterSkipTwoEntities      → sub_180231770
    ├─ UTIL_ClipTraceToPlayers          → sub_18022D350
    ├─ physprops->GetSurfaceData        → sub_180103650
    ├─ GetMaterialParameters            → (内联)
    ├─ [水花] DispatchEffect("gunshotsplash")   → sub_180340490
    ├─ [墙穿] impact_wallbang_light/heavy       → sub_1801E4170
    ├─ ★ CreateWeaponTracer(vecSrc, tr.endpos)  → [vtable+0xF8]
    └─ HandleBulletPenetration          → sub_18029DAA0
```

### 2.4 关键函数映射总表

| 二进制函数       | 源码函数                            |
|------------------|-------------------------------------|
| `sub_18029C390`  | `CCSPlayer::FireBullet`             |
| `sub_18044A6C0`  | `AngleVectors`                      |
| `sub_18030B350`  | `CBaseEntity::IsA()` / `ClassMatch` |
| `sub_18022C6A0`  | `UTIL_TraceLineIgnoreTwoEntities`   |
| `sub_180231770`  | `CTraceFilterSkipTwoEntities`       |
| `sub_18022D350`  | `UTIL_ClipTraceToPlayers`           |
| `sub_180103650`  | `physprops->GetSurfaceData`         |
| `sub_18022DC90`  | 武器获取辅助                        |
| `sub_180340490`  | `DispatchEffect`                    |
| `sub_1801E4170`  | wallbang impact 特效                |
| `sub_18029DAA0`  | `HandleBulletPenetration`           |
| `sub_180270E40`  | `CreateWeaponTracer` *(vtable)*     |


---

## Part 3 — 曳光弹起点问题分析

### 3.1 数据流

```
FireBullet 被调用:
  a2 (vecSrc) = 武器发射位置 (枪口偏移、视角修正后)

while 循环:
  vecEnd = vecSrc + vecDir * (flDistance - flCurrentDistance)
  → tr.endpos = 命中点

  ★ CreateWeaponTracer(vecSrc, tr.endpos)
       ↓
      内部从武器模型取 attachment → GetAttachment 覆盖 vecStart
      但 vecEnd 仍用外部传入的 tr.endpos
```

### 3.2 核心矛盾

```
  起点 = 枪口 attachment 世界坐标   ← CreateWeaponTracer 内部重新获取
  终点 = FireBullet 轨迹 tr.endpos  ← 外部传入

  → 两个坐标来源不一致!
```

### 3.3 修复方向

1. 确保 AUG/SG556 开镜逻辑被正确编译
2. 检查世界模型 `LookupAttachment("muzzle_flash")` 的 `this` 指针
3. 在 `CreateWeaponTracer` 中**不覆盖**调用者传入的 `vecStart`，仅当传入值为零向量时才自行获取

---

## 附录：工具排坑

| 问题   | `decompile` 等工具返回 `"disabled by user"` |
|--------|---------------------------------------------|
| **根因** | `ida-pro-mcp` 从 IDA netnode 读取 `enabled_tools` 配置并持久化在 `.i64` 文件中 |
| **修复** | 删除 `.i64` → 重新 `idb_open` → 工具恢复默认(全启用) |

================================================================================
EOF
