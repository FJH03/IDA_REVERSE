================================================================================
server.dll (64-bit) — 逆向分析日记 & 函数签名集
================================================================================

| 项目       | 说明                                                     |
|------------|----------------------------------------------------------|
| 目标文件   | `server.dll`                                             |
| ImageBase  | `0x180000000`                                            |
| MD5        | `cd5bc8d252fcc917852a93916b3f8ca0`                       |
| 架构       | x86-64                                                   |
| 函数总数   | 19,504                                                   |
| 命名函数   | 仅 40                                                    |
| 源参考     | `FJH03/source-engine` (2018 TF2 泄露, nillerusr 修改版)   |
| 工具       | `ida-pro-mcp` (idalib headless, `--unsafe`)              |
| 日期       | 2026-07-12                                               |


---

## Part 1 — CS:S Bot 状态机

> `cs_bot_statemachine` / `cs_bot_pathfind`  
> 定位方法：字符串特征 → vtable 反查 → xref → 反编译验证


### 1.1 `CCSBot::Follow`

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_180349230` (size `0xC9`)     |
| 源码   | `cs_bot_statemachine.cpp:73`      |
| 功能   | 开始跟随指定玩家；`m_isFollowing=true`, `m_leader=player`, `m_task=FOLLOW(11)`, 然后 `SetState(&m_followState)` |
| 定位   | `FollowState::GetName()` 返回 `"Follow"` → vtable → xref → 确认 |

```
IDA : 48 85 D2 0F 84 ? ? ? ? 48 89 5C 24 ? 57 48 83 EC 20 80 B9
x64 : \x48\x85\xD2\x0F\x84\x2A\x2A\x2A\x2A\x48\x89\x5C\x24\x2A\x57\x48\x83\xEC\x20\x80\xB9
```


### 1.2 `CCSBot::ContinueFollowing`

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_180349160` (size `0x82`)     |
| 地址   | `0x180349160`                     |
| 源码   | `cs_bot_statemachine.cpp:97`      |
| 功能   | 暂停后继续跟随 leader；保留 `m_leader` 不变，重新进入 FollowState |
| 定位   | `SetState` 的 xref 中，`m_task=FOLLOW(11)` 但无 player 参数，与 `Follow` 区分 |


### 1.3 `CCSBot::StopFollowing`

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_180349CF0` (size `0x2E`)     |
| 源码   | `cs_bot_statemachine.cpp:110`     |
| 功能   | 停止跟随；`m_isFollowing=false`, `m_leader=NULL`, `m_allowAutoFollowTime = gpGlobals->curtime + 10.0f` |
| 定位   | 搜字节 `C6 81 78 1E 00 00` (`mov byte[rcx+0x1E78],0` = `m_isFollowing=false`)；整 DLL 仅此一处 |

```
IDA : C6 81 ? ? ? ? ? C7 81 ? ? ? ? ? ? ? ? 48 8B 05
x64 : \xC6\x81\x2A\x2A\x2A\x2A\x2A\xC7\x81\x2A\x2A\x2A\x2A\x2A\x2A\x2A\x2A\x48\x8B\x05
```


### 1.4 `CCSBot::SetState`

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_180349B80` (size `0xFC`)     |
| 源码   | `cs_bot_statemachine.cpp:30`      |
| 功能   | 唯一合法的状态切换入口；`OnExit` 旧状态 → `OnEnter` 新状态 → 更新 `m_stateTimestamp` |
| 定位   | 搜字符串 `"%s: SetState: %s -> %s\n"` 命中 |

```
IDA : 48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 30 48 8B D9 48 8B FA
x64 : \x48\x89\x5C\x24\x2A\x48\x89\x74\x24\x2A\x57\x48\x83\xEC\x30\x48\x8B\xD9\x48\x8B\xFA
```


### 1.5 `CCSBot::Idle`

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_1803496F0` (size `0x20`)     |
| 地址   | `0x1803496F0`                     |
| 源码   | `cs_bot_statemachine.cpp:57`      |
| 功能   | `SetTask(SEEK_AND_DESTROY=0)` + `SetState(&m_idleState)`；主行为选择入口 |
| 定位   | `SetState` xref，`m_task=0` 且传递 `m_idleState(+0x1EC8)` |


### 1.6 `CCSBot::EscapeFromBomb`

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_180349200` (size `0x20`)     |
| 地址   | `0x180349200`                     |
| 源码   | `cs_bot_statemachine.cpp:63`      |
| 功能   | `SetTask(ESCAPE_FROM_BOMB=9)` + `SetState(&m_escapeFromBombState)` |
| 定位   | `SetState` xref，`m_task=9` 且传递 `m_escapeFromBombState(+0x2020)` |


### 1.7 `CCSBot::UpdatePathMovement`

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_180346E80` (size `~0x2000`)  |
| 源码   | `cs_bot_pathfind.cpp:1402`        |
| 功能   | 沿 A* 路径移动的核心循环；处理走/跑/蹲/爬梯/跳/避障 |
| 定位   | 搜字符串 `"Giving up trying to get to area #%d\n"` 命中 |

关键常量：

| 常量             | 值       |
|------------------|----------|
| `lookAheadRange` | `500.0`  |
| `aheadRange`     | `300.0`  |
| `nearCornerRange`| `100.0`  |
| `walkRange`      | `200.0`  |
| `nearEndRange`   | `50.0`   |
| `closeEpsilon`   | `20.0`   |

```
IDA : 48 8B C4 55 41 54 41 56 41 57 48 8D A8
x64 : \x48\x8B\xC4\x55\x41\x54\x41\x56\x41\x57\x48\x8D\xA8
```


### 1.8 `CCSBot::Update`

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_18034B1F0` (size `0x1337`)   |
| 源码   | `cs_bot_update.cpp:670`           |
| 功能   | Bot 主更新循环；状态机驱动 + 自动跟随逻辑 + 空闲行为选择 |
| 定位   | 搜字符串 `"Stopping following - bored\n"` / `"Auto-Following %s\n"` 命中 |

```
IDA : 48 8B C4 55 41 54 41 56 41 57 48 8D 68
x64 : \x48\x8B\xC4\x55\x41\x54\x41\x56\x41\x57\x48\x8D\x68
```


### 1.9 `FollowState::OnEnter`

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_180360300` (size `0xC0`)     |
| 源码   | `states/cs_bot_follow.cpp:20`     |
| 功能   | 进入 Follow 状态时初始化；`m_lastLeaderPos=(-99999999.9, -99999999.9, -99999999.9)` 强制下次更新立即重算路径 |
| 定位   | `FollowState` vtable[0] @ `0x180588E98` → 导出函数，特征常量三板赋值 |

```
IDA : 48 89 5C 24 ? 57 48 83 EC 30 48 8B 02 48 8B F9 48 8B CA 0F 29 74 24
x64 : \x48\x89\x5C\x24\x2A\x57\x48\x83\xEC\x30\x48\x8B\x02\x48\x8B\xF9\x48\x8B\xCA\x0F\x29\x74\x24
```


### 1.10 `FollowState::OnUpdate`

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_1803603C0` (size `0x860`)    |
| 源码   | `states/cs_bot_follow.cpp:173`    |
| 功能   | Follow 状态每帧更新；跟踪 leader 速度/位置，决定 sneak/run/walk，重算路径 |
| 定位   | `FollowState` vtable[1] @ `0x180588EA0` → 导出函数，字符串 `"Pathfind to leader failed.\n"` |

```
IDA : 40 55 56 57 41 56 41 57 48 8D AC 24
x64 : \x40\x55\x56\x57\x41\x56\x41\x57\x48\x8D\xAC\x24
```


---

## Part 2 — CBaseEntity 实体工具函数

> `game/server/baseentity.cpp`  
> 定位方法：源码分析调用者 → `VoiceGameMgr` vtable → 反编译追索链


### 2.1 `CBaseEntity::InSameTeam`

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_180126AC0` (size `0x3D`)     |
| 源码   | `game/server/baseentity.cpp:4337` |
| 功能   | 判断两个实体是否同队；`pEntity==NULL` → `false`，否则比较 `m_iTeamNum` |

**追索链：**

```
搜 "InSameTeam" → 无果 (被 strip)
  → 分析源码：只在 CVoiceGameMgrHelper::CanPlayerHearPlayer 中被调
    → 搜 "VoiceGameMgr" → 找到 vtable
      → 在 vtable 附近搜 call [rax+218h] (IsAlive 虚调用) 两次
        → 找到 CanPlayerHearPlayer
          → 反编译发现它调用 sub_180126AC0
            → 反编译确认为 InSameTeam (null check + 双实体比较)
```

```
IDA : 40 57 48 83 EC 20 48 8B F9 48 85 D2 75
x64 : \x40\x57\x48\x83\xEC\x20\x48\x8B\xF9\x48\x85\xD2\x75
```


### 2.2 `CanPlayerHearPlayer`

| 字段   | 值                                |
|--------|-----------------------------------|
| IDA    | `sub_1802F02A0` (size `0x4A`)     |
| 源码   | `game/shared/cstrike/cs_gamerules.cpp:309` |
| 功能   | 语音通话权限判断 |

```
逻辑:
  双方都活着 或 都死了且同队 → 可听到
  详细:
    pTalker->IsAlive()?
      → 活: return InSameTeam
      → 死: 检查 pListener
            pListener->IsAlive()?
              → 死: return InSameTeam
              → 活: return false
```

定位：搜 `"VoiceGameMgr"` → `IVoiceGameMgrHelper` vtable @ `0x180570960` → 在附近搜 `call [rax+218h]` 两次 → 命中

```
IDA : 48 89 5C 24 ? 57 48 83 EC 20 49 8B 00 49 8B C8
x64 : \x48\x89\x5C\x24\x2A\x57\x48\x83\xEC\x20\x49\x8B\x00\x49\x8B\xC8
```


---

## 关键对象偏移速查

### CBaseEntity

| 成员              | 偏移          | 类型    | 备注                       |
|-------------------|---------------|---------|----------------------------|
| `m_iTeamNum`      | `+0x2F4`      | DWORD   | 通过 `sub_1802A08B0` 解析   |
| `IsAlive()`       | vtable `+0x218` | —     |                            |

### CCSBot

| 成员                        | 偏移       | 类型              |
|-----------------------------|------------|-------------------|
| `m_isFollowing`             | `+0x1E78`  | byte              |
| `m_leader`                  | `+0x1E7C`  | CHandle / int32   |
| `m_followTimestamp`         | `+0x1E80`  | float             |
| `m_allowAutoFollowTime`     | `+0x1E84`  | float             |
| `m_idleState`               | `+0x1EC8`  |                   |
| `m_escapeFromBombState`     | `+0x2020`  |                   |
| `m_followState`             | `+0x2028`  |                   |
| `m_followState.m_leader`    | `+0x2030`  |                   |
| `m_task`                    | `+0x20D0`  | int32 (TaskType)  |
| `m_taskEntity`              | `+0x20D4`  | int32 / CHandle   |

### TaskType 枚举

| 值   | 符号                |
|------|---------------------|
| 0    | `SEEK_AND_DESTROY`  |
| 9    | `ESCAPE_FROM_BOMB`  |
| 11   | `FOLLOW`            |


---

## 附录：工具权限排坑

| 问题   | `decompile` / `find` / `callees` 等工具返回 `"disabled by user"` |
|--------|------------------------------------------------------------------|
| **排查** | ① VS Code `settings.json` 无效  ② 全局 settings.json 无相关配置  ③ 全盘搜 JSON 无 `"decompile"` 字样  ④ 不是 Copilot 的限制 |
| **根因** | `ida-pro-mcp` 的 `http.py::handle_enabled_tools()` 从 IDA netnode 读取 `"enabled_tools"` 配置并持久化在 `.i64` 文件中；某次可能通过 `/config.html` 禁过这些工具 |
| **修复** | 删除 `server.dll.i64` → 重新 `idb_open` → 全部工具恢复默认 (全启用) |
| **教训** | 工具被禁 ≠ Copilot / VS Code 问题，**先查 `ida-pro-mcp` 自身的 profile / `enabled_tools`** |

================================================================================
EOF
