import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const API_PACKAGE = 'vram-governor/internal/api';
const TOP_RESIDENCY = 'TestControllerResidencySignedNodeBoundary';
const QUERY_CHILD = `${TOP_RESIDENCY}/uncertain-controller-query`;
const RESTART_CHILD = `${TOP_RESIDENCY}/controller-restart-query-first`;
const TOP_COMFY = 'TestControllerNativeComfyBoundaryIsFailClosed';
const TOOLCHAIN_REL = '.cache/gopath/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.4.windows-amd64/bin/go.exe';
const TOOLCHAIN_SHA256 = '8e8356be1603abff526f52c0d5fe887fb4d77b000f310d298ad10cd33e7471e6';

const expectedPins = [
  ['internal/workloads/manager.go',411178,'e661094ed488140743780e413c1dbe42197ae2aab99ddb1b3bb08041c29fe358'],
  ['internal/workloads/manager_test.go',290449,'2b7db9a3ed001330ddafc777788dd0e766508be01f426270fb0d9f009c887c8a'],
  ['internal/workloads/residency.go',112173,'341f55bd6a4e2ee374b8d38562bd5aeab93af1166bdac84db39208afdc53522e'],
  ['internal/api/node_commands.go',79097,'20047d49a8628c65c71efa23c6b3c627279783ed545046a51851e8c5187eb550'],
  ['internal/api/node_commands_test.go',80334,'b77fec982aae8fc6595dbe05b1f3ed14fa38c570fd156478433493b5e5399bc2'],
  ['internal/api/ws.go',58722,'2a60e84306871a08e372c811d8e2edb82f24d33e94639de988b491be1ed10ead'],
  ['internal/api/ws_test.go',66923,'a2334022efa245687a128c024e0e010640db1b2d7b15421c18ddb95f0744eed3'],
  ['scripts/verify-runtime-profile-projection.mjs',185643,'a099d5e788a1461a78206700680b741075e35e9b701518e287721b1021fd0aa1'],
  ['internal/api/node_commands_linux_test.go',366,'0d588333abdfff48b2948d4ce235c0611463990c75e3c211694f684ae1982904'],
  ['internal/api/workloads_http_test.go',86607,'873645df94191446ac33c7fbdf9742081b90cc2424fb171dbabc0019224c6d50'],
];

// The complete direct Go package source set is pinned as well as the accepted
// fleet pins. This detects an unreviewed API compile-input addition/removal.
const apiClosurePins = [
  ['internal/api/admin.go',20415,'d3294e012bc23b38706614c3ba6621b79f94316e604516cde47cc183745d0a62'],
  ['internal/api/amd_telemetry_test.go',1389,'67e0058881383ec7483ee298a3d5dff1ef5f170610c3950dac369f653b9d1f0f'],
  ['internal/api/artifacts.go',4545,'165670ba55745cc6b5934040a0121e8ffb6551f7a3a483eed0ce036f66f7c0e1'],
  ['internal/api/auth.go',13478,'771624db8a5766a0d864d0a394be5c48ef9b948fd9d11bc5534707bb947979b1'],
  ['internal/api/auth_test.go',9156,'5bd71357dc681db9149b2f750d7abbed66223410493b4120590acb32901e8259'],
  ['internal/api/config.go',28375,'d040c82ec07e52ccea5da3e830905a59eefdb1ff3b056f6033c228f81e241b47'],
  ['internal/api/config_test.go',28562,'09e9c51467ddc68745ff4379a7e379b9a526130a9af238d9a61dec4de2bac808'],
  ['internal/api/creator_studio.go',27770,'1cf93b90608f65a15cb114995eac310250c65831846c959e668a58db11f0b2c5'],
  ['internal/api/creator_studio_test.go',32887,'9576819d39059c102e7de48b289d92a541fcb67dee6c1e8c0393a9859a39f95c'],
  ['internal/api/http.go',10651,'570f7696f5c0ecdfdd917561263daeb785d7b8272dbb73540375e161266aff54'],
  ['internal/api/incidents.go',11909,'3881643f83386171a1702d1ee3d56e6c03909fb988b4f78d1c3a1319a99eef8f'],
  ['internal/api/jobs_http.go',3897,'b7caa43995565bffc54be7cf0f0e2c5643d918f00b377cb450a85b7911da188d'],
  ['internal/api/liveness_incident_test.go',3411,'8e4b91ad242ccc9890a117ce0deea339b494fb5e458bbd7978b0350d5fc6bea7'],
  ['internal/api/native_checkpoint_e2e_test.go',46189,'52095684c9fb70dca4b644b8d68676909dd5b3ba4081c78288a7773f8c0188a5'],
  ['internal/api/node_commands.go',79097,'20047d49a8628c65c71efa23c6b3c627279783ed545046a51851e8c5187eb550'],
  ['internal/api/node_commands_linux_test.go',366,'0d588333abdfff48b2948d4ce235c0611463990c75e3c211694f684ae1982904'],
  ['internal/api/node_commands_test.go',80334,'b77fec982aae8fc6595dbe05b1f3ed14fa38c570fd156478433493b5e5399bc2'],
  ['internal/api/node_enrollment.go',4113,'0f0a138c7ded10751a2501f42efa56e944eae73ab17c189a05951ae843282361'],
  ['internal/api/node_enrollment_test.go',3753,'e11ef56e11fe43587b432b259c9ad2a3b0aff7fcfe43dc849a8efbe8081d4afb'],
  ['internal/api/server.go',30134,'492ea84fb0e0170acd9e62845798699d649609171a36f56c38be9c8564c859d4'],
  ['internal/api/smart_plugs.go',11996,'0eb2540598db9c7e9f8c7b308d40916a1f433c1ba82e0d4b9aeedadcf9105995'],
  ['internal/api/smart_plugs_test.go',11866,'ac01e2dfd2aed523270b1509b7e3159059d55ca89440ccc27fba6f81ad791603'],
  ['internal/api/workloads_http.go',37249,'c9e14445bad59e61944517b4cd8d6209ab931f0ec2b272c484a093b5efee0eb1'],
  ['internal/api/workloads_http_test.go',86607,'873645df94191446ac33c7fbdf9742081b90cc2424fb171dbabc0019224c6d50'],
  ['internal/api/ws.go',58722,'2a60e84306871a08e372c811d8e2edb82f24d33e94639de988b491be1ed10ead'],
  ['internal/api/ws_auth_test.go',2620,'f5ad154ab9e4d5e7553093542a8ecf13a019731256454d9c2e1a2a63dc06dcb0'],
  ['internal/api/ws_test.go',66923,'a2334022efa245687a128c024e0e010640db1b2d7b15421c18ddb95f0744eed3'],
];
const modulePins = [
  ['go.mod',undefined,'0b673b9e04273739530d443e36107ddb6f4d496b91b8b89a16c95cc1539374da'],
  ['go.sum',undefined,'343b5aee4865978a14726744ab7ca4a6b812fc5dcbca4273c14619364d62dd3d'],
];

const dependencyClosurePins = [
  ['internal/artifacts/s3.go',7721,'c49332fdf049f631b75af5dac3decd3541ecf2d1f8611cf190c628adbe36f999'],
  ['internal/artifacts/store.go',4665,'d2da675c12f37fb09b4de6fa36fc4603e2095b7fd0f8911da1a2c74cf7268d2d'],
  ['internal/checkpointgpuobserver/observer_linux.go',49523,'b2323c674bfdc1e8511d2d071bc79e255b90141bda4c65ab1a70c2885fdf6d62'],
  ['internal/checkpointgpuobserver/observer_other.go',298,'014b9a548acef3f1a3e358a282904587a528eaebf1ea7d6f683b991eaa91d736'],
  ['internal/checkpointgpuobserver/protocol.go',15320,'4587b426cdda642dd783f3ca35f5b2557c119f9eb5ec6c0b34c6275f38e9def6'],
  ['internal/domain/auth.go',1195,'d1c481154d8f5b0041be1f5e48c8923003429ddca82a08d8a9733cdb1de57762'],
  ['internal/domain/creator_studio.go',4617,'63b32dcad0eb0b41a3f78ca1cc2b48d05076915418da1c7256fe9205b91cf9b3'],
  ['internal/domain/domain.go',34263,'aeb0711d61331031df80711cc18faeb955e07375a6747542acb1346cfe5b587f'],
  ['internal/domain/node_enrollment.go',422,'8c58c984444c06b918d54e3a9fd4298ac4f6817b218739586ba78dd1cf33d6e8'],
  ['internal/domain/workload.go',35366,'a70d381092b20df1c319a9af016be8499d41c3f131e4f290d1fc2d39580d968d'],
  ['internal/jobs/manager.go',22852,'3229f360ab133018e8b834f04f2dd10917114ddfca70af230a90aed07ec2533f'],
  ['internal/jobs/worker.go',7214,'3de464e682c07d4e7e3dbb471fde672e28369504f41ee04fd0134b5286c30f79'],
  ['internal/logging/logging.go',2569,'77327a4f79e9574d1b05e91c59f6a460d5bc1fd7af2703988bddac3310e2579f'],
  ['internal/nodeagent/agent.go',17266,'f06f7d21e32bd1c0b07691cc52e344379643c01ffc89a7a5c4e656dcecb1b60b'],
  ['internal/nodeagent/amd.go',3211,'95aa081a7a4a291f688181d18981b94b071b4e10849964a25eabf5466cb48be8'],
  ['internal/nodeagent/checkpoint_custody.go',32727,'e82a71a361f1573cab284c1d58beaeb140b8108e027f826202ccaa406391764b'],
  ['internal/nodeagent/checkpoint_custody_linux.go',96597,'5e3d63292f91b2937d9e81494b0bb50a81801a9dc4fd07497c2d757252e43497'],
  ['internal/nodeagent/checkpoint_custody_other.go',3858,'52794684c55f5630a271771e59fb6fcdd3893c7603b7c52a024f01c89e1ff95b'],
  ['internal/nodeagent/checkpoint_device_binding.go',6372,'be0a04a5bd346adeb1d08e12f91dd77b746702997a2f5a9ec1c745dd5f5ee36f'],
  ['internal/nodeagent/checkpoint_device_binding_linux.go',32873,'9009cd022986efe49651259bc9bd8203b5b24687416f1185b79c2ee61a8d2eb4'],
  ['internal/nodeagent/checkpoint_device_binding_other.go',349,'f7e69427ee4ffb2b33958e5a761a9d6eeedc9437b7816390eb7baaa1f6887e32'],
  ['internal/nodeagent/checkpoint_fixed_launcher.go',16817,'648f71fd7efc2b4764cf90b36770969b2add94e84f5ad293bcbb66c8cf96a0a4'],
  ['internal/nodeagent/checkpoint_fixed_launcher_linux.go',28346,'bd4466eeb802b1fb28a69728e8b8e87125561a587748ebd3cdbca6501caad600'],
  ['internal/nodeagent/checkpoint_fixed_launcher_other.go',260,'52bde2fed8efc7483849772a896b17278bf181e6f68d4e2aefd8672e41c0af07'],
  ['internal/nodeagent/checkpoint_host_gpu_bridge.go',2093,'c62d42c0e9288453692fbce4330e8d7b1472642cdb3d28227b5c0ee98ff7c75f'],
  ['internal/nodeagent/checkpoint_host_gpu_bridge_linux.go',30292,'1a1667e1e724b863d53c9c32bf10789037fe5542709cb5b05e1a6f3da1e9e65f'],
  ['internal/nodeagent/checkpoint_host_gpu_bridge_other.go',365,'a570ac35240053bc43e08e8a47900c00192df3dbb4fc7d8f06cdbdc446e7b9e2'],
  ['internal/nodeagent/checkpoint_identity.go',8105,'fc342ed52d4bb9c73fa8ede8022230de32b0a7f98effad711abfa105258ceae1'],
  ['internal/nodeagent/checkpoint_identity_linux.go',33734,'5bc2e4b97c179620fd4950d73c2f850097505946794b3ea8606297644303b861'],
  ['internal/nodeagent/checkpoint_identity_other.go',354,'ea8296f27d1f81dedfb050dd79e1649faced53161769064ce8ee33c22df3c933'],
  ['internal/nodeagent/checkpoint_launch_plan.go',19291,'02ac5cdd48e417c6f8fe835914bad32130e3e6df7f61bf45b6e572e3f33d3983'],
  ['internal/nodeagent/checkpoint_launch_plan_linux.go',7234,'d0875dd484451642f6e6e891400a2888734419a12ca86adeeaf83e8fdc577334'],
  ['internal/nodeagent/checkpoint_launch_plan_other.go',422,'d31384fba2ca401badaefab142ba438ec633ccd736030bb845669261fa1cc0a2'],
  ['internal/nodeagent/checkpoint_lifecycle_broker.go',6119,'ad6736e0996570f6a7b6f537450afaecb4c61c679c4b48ce440716feea727571'],
  ['internal/nodeagent/checkpoint_lifecycle_broker_linux.go',93873,'43f7bc12cc692ac98d9e383a119a12705299910fa2a2bf8dcb44cfbb4000eb0a'],
  ['internal/nodeagent/checkpoint_lifecycle_broker_other.go',505,'022af1f95b2a8dbecf7d50a687da3ea47eafd1efeff70844ae5576c0e3cf070e'],
  ['internal/nodeagent/checkpoint_local_observer.go',14231,'772be840ff916ba083ee948e091d33f2b1c3a2213f6bb0b197072131414e0e97'],
  ['internal/nodeagent/checkpoint_local_observer_linux.go',45446,'ee70ecbd7b6ed1e23836542b6987861a52451644928c8e38cf18134bd72e18b0'],
  ['internal/nodeagent/checkpoint_local_observer_other.go',440,'23d1327a906aff06f40b54003673cf273a70038bf1b337ba23ce0b5f337e3d6d'],
  ['internal/nodeagent/checkpoint_managed_binding.go',12904,'b624c65ce84e583f14c12078483b6956e9978094cc8fdcab7017d7a32319a5fa'],
  ['internal/nodeagent/checkpoint_managed_binding_linux.go',19118,'b7750da624deefd62c4d58a846773f997651a73e0670afd7ca801f3ce58cc82a'],
  ['internal/nodeagent/checkpoint_managed_binding_other.go',312,'f3f810e438dadf8ba1cb9fc0784dc2a483cb63c5ad2bac665e4c7cc9bd3e001e'],
  ['internal/nodeagent/checkpoint_plan_rotation.go',18136,'dd8bedf72a0494e3a6d241095de3adb833e365cb4f4376d50e3721745449aaa5'],
  ['internal/nodeagent/checkpoint_plan_rotation_linux.go',1697,'ef8ed0a10931e73187f39ccdbaf3fc21057d7d56d065600bf47fbfd1ec5c373b'],
  ['internal/nodeagent/checkpoint_plan_rotation_other.go',214,'7a01a7b35024249ec73c2e0ea63e5a62274bdd7e4dda5a2c2180f906491b876d'],
  ['internal/nodeagent/checkpoint_unit_identity.go',10137,'21029d1090c4c87b0b88f0eaf979ef64ab0dc1191fd728210b34d024afec5402'],
  ['internal/nodeagent/checkpoint_unit_identity_linux.go',7696,'aae79e135fc31990c06c344e4f3bce01acdbf469878e8dc605e77c3eb9d419f1'],
  ['internal/nodeagent/checkpoint_unit_identity_other.go',335,'182dc164b388f292d7a4df1a4683368f833ce0a12d2547e6416c1f3e63615402'],
  ['internal/nodeagent/checkpoint_unit_lifecycle.go',6468,'86c69092df3360b62d56f03a622d4e2fc4089def3d610aadace952d391dde4d3'],
  ['internal/nodeagent/checkpoint_unit_lifecycle_linux.go',66880,'0a2d8359028e36aa9a60579de2667bb0f4b48640691acc32b47abf032743f804'],
  ['internal/nodeagent/checkpoint_unit_lifecycle_other.go',1170,'de45d727030f17267d64a6403c38ec56ad4e7202962b056ad81040993775c56f'],
  ['internal/nodeagent/comfy.go',3471,'01a22d57e8fcc54bbd049f51ccbe621cf37054df00b0bdf7bded3f5f87e8e1f5'],
  ['internal/nodeagent/commands.go',293117,'9a1586d220df11281403d5109b64d527ca15b393b978cd2b52ce6a41f2612f2f'],
  ['internal/nodeagent/config.go',20786,'c27f09767a4d926a41dd47d0855afc009075e86f828b2730fa06009d98d482ba'],
  ['internal/nodeagent/disk_linux.go',449,'7f40a692c2cab59e1a101212ab6981311d6628b78954af231720593492db436f'],
  ['internal/nodeagent/disk_other.go',110,'042b9beae80c5ae3dad091fa607c5d947130e784335e119354cc2db6ce63c166'],
  ['internal/nodeagent/gpu.go',3877,'c6eb2c0900667978ca0ca3c6173f4364a27ff6689e2ec9e44be0c032fc3215da'],
  ['internal/nodeagent/llamacpp.go',15364,'00b86edeba2a350651fbfc1d053518a05c4aee2bb2f9a4e38a121f1d39e80d5e'],
  ['internal/nodeagent/llamacpp_checkpoint.go',91126,'c384b92efa33af6350e9c3157aa1aed307639219ed8c188bcf33bb349da953ac'],
  ['internal/nodeagent/probe.go',5240,'c8698ad852a83c0aa1bdd006b88a342a438683f22cba68950521c5edb4f07aa4'],
  ['internal/nodeagent/system.go',5185,'f0c5d1b2547551e1cad0d5dd7af004563b651d93d30332439c57d95d285a3bbe'],
  ['internal/nodeagent/warmram.go',45045,'cde52ab10e297b96c4b0ac471d684e373fbde1943c5d1de9f7e3cb5ab74bbb6b'],
  ['internal/nodeagent/warmram_linux.go',11970,'1774c2be17e47bb5cd0b5265ebc2b477ee91dddb1522a7b7020a64fae14df9e5'],
  ['internal/nodeagent/warmram_other.go',1596,'9a6392ff0396f6947004d2cbe9bcb63647e5d0502956704f89d8a1cec41aebd1'],
  ['internal/nodetransport/limits.go',603,'0c7453ec051d7f69e34f65bc1c5fdf4e512287a709f75dd409574f24d0bf5a0b'],
  ['internal/probe/probe.go',18774,'d788aac5199af61981e80f149065f9c75183a573ee2e653bcb5a03ab413a5ff2'],
  ['internal/runtime/driver.go',18637,'1f5760c4b7fd864cc578a4cf99b2120d76ce3c49e2dca7a886e5213aafdb1cd2'],
  ['internal/runtime/llamacpp/driver.go',54344,'de5eefb2db432caa4db5994758d581ee2b4d26a34dac454a94ed2f36c172b97a'],
  ['internal/safefile/nofollow.go',1193,'ff38c0ce72687dc21b0d63f9305d398d8a284e3b33738e6ccb06ad109acaca24'],
  ['internal/safefile/nofollow_other.go',308,'07aab5d70368e9014b83738e8c50d0124034541fd5e69112a8d0a32536e02d08'],
  ['internal/safefile/nofollow_unix.go',539,'092bb4c619bd20448aa0c50b996c7338d612e5f767322532b77735cedf1074ea'],
  ['internal/safefile/nofollow_windows.go',1656,'f64efb00d55cb2813e5d275c122e2f9faea80dcc77617123cbd292407bef17a4'],
  ['internal/store/llm_displacement.go',28568,'58cd8165bc9777752ba3964fe3fdfdef28d3d113071ce3067504110c4c2d6f9b'],
  ['internal/store/memory.go',77647,'e1347b2e9f85ee11110117fb73a66ea8a03ef95c4dccf396d714df382eb1dcea'],
  ['internal/store/node_enrollment.go',1914,'353d514d77dbe46ced044c8fe8bbe0758e353871271c4fa11db1dd8a45d5dd5c'],
  ['internal/store/postgres_core.go',11281,'464614c7ed5bb1ebbdc878b40cd8a82db88dd0ca099fe4423da7c6d71168d980'],
  ['internal/store/postgres_llm_displacement.go',8702,'bbf4e57483de04c810837fb7ce65f2add164bba3c031c1b08110e83382929298'],
  ['internal/store/postgres_node_enrollment.go',2504,'44ca2bde6dc9dec2cc6de77ee02988a92741a0274a9439cf3840a67d09047818'],
  ['internal/store/postgres_sessions.go',1166,'08c4dcaa4660c3655afff3d83a28a886353bfbefa11b4076069605fbd884f845'],
  ['internal/store/postgres_workloads.go',104934,'590f6c35251d31c5a7e5e6ea36a6256628ba74887e06a15dc3c0ab6d50edc1e2'],
  ['internal/store/store.go',43542,'f04be85ef91e808d7a38751773cf164822190602064856c8365ccb45e4aed4cc'],
  ['internal/workloads/adapter.go',15966,'5dd718e7cb0019f6e751ffc99510ce2580b81add0caede13a740f2caaaf0b057'],
  ['internal/workloads/adapters.go',104746,'04c6dc58dd827ba4ab88fcf3d19ffe2885441d1de54599572c4630e2dc89f2d0'],
  ['internal/workloads/artifact_results.go',6477,'3f074a104b749f47042eb46bcda9843ae3cb4bd41ded3d117cf2df2c79f21aa4'],
  ['internal/workloads/creator_studio.go',17128,'ec9eada863fd35ac7c1913effc0dc4784274e81323ac3f5b3268ce8011382d28'],
  ['internal/workloads/llamacpp_checkpoint.go',117254,'59788753f293306bb4619cc4d4a6d4b04f9672c5ef1dd16391f519d91b7cb8dd'],
  ['internal/workloads/managed_comfy.go',10577,'6734458eedaae4ea5cd35b26ea447625099280d85858b2c95754416fbf1598fa'],
  ['internal/workloads/manager.go',411178,'e661094ed488140743780e413c1dbe42197ae2aab99ddb1b3bb08041c29fe358'],
  ['internal/workloads/notifications.go',10387,'761b40924219d6c6f00dbf6e54e86a3fdc1bc8fd091f47f9a9290a2f087cc1ea'],
  ['internal/workloads/power_profiles.go',7231,'0ac1e40860acb664547132d58ca379be08b1289be54d1be5a83fb9249d7ff711'],
  ['internal/workloads/preview.go',5463,'c5a59edd85e390550f9836a4d0ea2a51a1e4b37b22c69babc348bdd83000353a'],
  ['internal/workloads/residency.go',112173,'341f55bd6a4e2ee374b8d38562bd5aeab93af1166bdac84db39208afdc53522e'],
  ['internal/workloads/warmram.go',60820,'09134f1edfa75f3a49033a46fd209a822ad55ce41edf367b3ba9a49e360b59e5'],
  ['internal/wsproto/messages.go',53446,'d606b64d36f3ed64f303a7c99a8dec0b6065caf45c2418df540f49cb02609bb3'],
];
const primaryEvents = [
  'node_handle_replay_exact','warm_verified','warm_replay_exact','cleanup_cold','restart_replay_exact',
  'signed_expiry_zero_mutation','stale_rejected','envelope_rejected','empty_capability_rejected',
  'rollback_observed','mismatch_rollback_observed','load_hot','unload_cold','controller_restart_replay_exact',
  'uncertain_restart_query_first','live_pending_wrong_resource_rejected','live_pending_runtime_identity_rejected',
  'query_authoritative','uncertain_intent_reconciled','offline_rejected',
];
const queryConfirmations = ['late_result_reconciled','live_pending_wrong_resource_rejected','live_pending_runtime_identity_rejected','query_authoritative'];
const restartConfirmation = ['uncertain_restart_query_first'];
const comfyEvents = ['native_comfy_reclaim_denied_zero_free','native_comfy_capability_false_zero_free'];
function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function readBounded(relative, max = 64 * 1024 * 1024) {
  const absolute = path.resolve(root, relative);
  if (!absolute.startsWith(`${root}${path.sep}`)) throw new Error('source path escaped workspace');
  const bytes = fs.readFileSync(absolute);
  if (bytes.length > max) throw new Error('pinned source exceeds fixed bound');
  return bytes;
}
function verifyPin([relative, expectedBytes, expectedHash]) {
  const bytes = readBounded(relative);
  if ((expectedBytes !== undefined && bytes.length !== expectedBytes) || sha256(bytes) !== expectedHash) {
    throw new Error('pinned source drift detected');
  }
  return bytes;
}
function verifySourcePins() {
  for (const pin of expectedPins) verifyPin(pin);
  for (const pin of apiClosurePins) verifyPin(pin);
  for (const pin of dependencyClosurePins) verifyPin(pin);
  for (const pin of modulePins) verifyPin(pin);
  const closure = [...apiClosurePins,...dependencyClosurePins];
  const directories = [...new Set(closure.map(([relative]) => path.posix.dirname(relative)))].sort();
  const expectedByDirectory = new Map(directories.map((directory) => [directory,closure.filter(([relative]) => path.posix.dirname(relative)===directory).map(([relative])=>path.posix.basename(relative)).sort()]));
  for (const directory of directories) {
    const actual = fs.readdirSync(path.join(root,directory)).filter((name) => name.endsWith('.go') && (directory==='internal/api'||!name.endsWith('_test.go'))).sort();
    assert.deepEqual(actual,expectedByDirectory.get(directory),'pinned compile source inventory changed');
  }
  const closureDirs = new Set(directories);
  for (const [relative] of closure) {
    const source=readBounded(relative).toString('utf8');
    for (const match of source.matchAll(/"vram-governor\/(internal\/[^"]+)"/g)) {
      const importDir=match[1];
      assert(closureDirs.has(importDir),'internal compile dependency is not pinned');
    }
  }
  assert.equal(expectedPins.length, 10);
  assert.equal(apiClosurePins.length, 27);
  assert.equal(dependencyClosurePins.length, 94);
  return true;
}

function sourceContracts() {
  verifySourcePins();
  assert(readBounded('go.mod').toString('utf8').startsWith(`module ${API_PACKAGE.split('/internal/')[0]}\n`),'API module identity changed');
  const tests = readBounded('internal/api/node_commands_test.go').toString('utf8');
  const wrapper = readBounded('internal/api/node_commands_linux_test.go').toString('utf8');
  const query = readBounded('internal/api/workloads_http_test.go').toString('utf8');
  assert.match(wrapper,/func TestControllerResidencySignedNodeBoundary\(t \*testing\.T\)\s*\{\s*runControllerResidencySignedNodeBoundary\(t\)\s*\}/);
  assert.match(tests,/func TestControllerNativeComfyBoundaryIsFailClosed\(t \*testing\.T\)\s*\{\s*runControllerNativeComfyBoundary\(t\)\s*\}/);
  assert.match(tests,/if !t\.Run\("uncertain-controller-query", TestControllerRejectsForgedAuthoritativeObservation\)/);
  assert.match(tests,/if !t\.Run\("controller-restart-query-first", TestAdminNodeCommandUncertainReplayUsesQueryRecovery\)/);
  for (const marker of [...new Set([...primaryEvents,...queryConfirmations,...restartConfirmation,...comfyEvents])]) {
    assert(tests.includes(`boundaryEvent(t, "${marker}")`) || tests.includes(`"${marker}"`), 'source-derived marker inventory changed');
  }
  assert.match(tests,/if drainErr != nil \|\| drainResult == nil \|\| len\(drainResult\.TransitionIDs\) != 0/);
  assert.match(tests,/target\.SupportsAcceleratorReclaim \|\| freeCalls\.Load\(\) != 0/);
  assert.match(query,/func TestControllerRejectsForgedAuthoritativeObservation\(t \*testing\.T\)/);
  assert.match(query,/func TestAdminNodeCommandUncertainReplayUsesQueryRecovery\(t \*testing\.T\)/);
  return tests;
}

function event(action, test, output = undefined) {
  const row = {Action:action,Package:API_PACKAGE};
  if (test !== undefined) row.Test = test;
  if (output !== undefined) row.Output = output;
  return row;
}
function expectedTranscript() {
  const rows = [];
  const mark = (test, names) => names.forEach((name) => rows.push(event('output',test,`    node_commands_test.go:88: boundary pass: ${name}\n`)));
  rows.push(event('run',TOP_RESIDENCY));
  mark(TOP_RESIDENCY,primaryEvents);
  rows.push(event('run',QUERY_CHILD));
  rows.push(event('name',TOP_RESIDENCY));
  mark(TOP_RESIDENCY,queryConfirmations);
  rows.push(event('run',RESTART_CHILD));
  rows.push(event('name',TOP_RESIDENCY));
  mark(TOP_RESIDENCY,restartConfirmation);
  rows.push(event('pass',TOP_RESIDENCY));
  rows.push(event('nested-pass',QUERY_CHILD),event('nested-pass',RESTART_CHILD));
  rows.push(event('run',TOP_COMFY));
  mark(TOP_COMFY,comfyEvents);
  rows.push(event('pass',TOP_COMFY),event('pass'));
  return rows;
}
function verboseTranscript(rows) {
  return rows.map((row) => {
    if (row.Action==='run') return `=== RUN   ${row.Test}\n`;
    if (row.Action==='name') return `=== NAME  ${row.Test}\n`;
    if (row.Action==='name-raw') return row.Output;
    if (row.Action==='pass') return row.Test===undefined?'PASS\n':`--- PASS: ${row.Test} (0.00s)\n`;
    if (row.Action==='nested-pass') return `    --- PASS: ${row.Test} (0.00s)\n`;
    if (row.Action==='fail') return `--- FAIL: ${row.Test} (0.00s)\n`;
    if (row.Action==='skip') return `--- SKIP: ${row.Test} (0.00s)\n`;
    return row.Output;
  }).join('');
}
function parseVerboseOutput(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text,'utf8') > 4*1024*1024) throw new Error('test stream bound exceeded');
  const lines = text.split(/\r?\n/).filter((line) => line.length !== 0);
  if (lines.length > 20000) throw new Error('test event bound exceeded');
  for (const line of lines) if (Buffer.byteLength(line,'utf8') > 16*1024) throw new Error('test event line bound exceeded');
  return lines;
}
function reduceEvents(lines) {
  const timeline = [
    ['run',TOP_RESIDENCY], ...primaryEvents.map((name) => ['marker',TOP_RESIDENCY,name]),
    ['run',QUERY_CHILD], ['name',TOP_RESIDENCY], ...queryConfirmations.map((name) => ['marker',TOP_RESIDENCY,name]),
    ['run',RESTART_CHILD], ['name',TOP_RESIDENCY], ...restartConfirmation.map((name) => ['marker',TOP_RESIDENCY,name]),
    ['pass',TOP_RESIDENCY], ['nested-pass',QUERY_CHILD], ['nested-pass',RESTART_CHILD],
    ['run',TOP_COMFY], ...comfyEvents.map((name) => ['marker',TOP_COMFY,name]),
    ['pass',TOP_COMFY], ['package-pass',undefined],
  ];
  let started = false;
  let packagePassed = false;
  let cursor = 0;
  const pendingNested = [];
  for (const line of lines) {
    const run = line.match(/^=== RUN   ([A-Za-z0-9_./-]+)$/);
    const nameTransition = line.match(/^=== NAME  ([A-Za-z0-9_./-]+)$/);
    const pass = line.match(/^--- PASS: ([A-Za-z0-9_./-]+) \([0-9]+(?:\.[0-9]+)?s\)$/);
    const nestedPass = line.match(/^    --- PASS: ([A-Za-z0-9_./-]+) \([0-9]+(?:\.[0-9]+)?s\)$/);
    const failedOrSkipped = /^\s*--- (?:FAIL|SKIP):/.test(line);
    if (!started) {
      if (run && run[1] === TOP_RESIDENCY) {
        const expected = timeline[cursor];
        if (!expected || expected[0] !== 'run' || expected[1] !== run[1]) throw new Error('test stream did not start with selected parent');
        started = true;
        cursor++;
        continue;
      }
      throw new Error('test stream did not start with selected parent');
    }
    if (!started || packagePassed) throw new Error('test lifecycle outside package bounds');
    if (failedOrSkipped) throw new Error('failed or skipped selected test');
    if (run || nameTransition || pass || nestedPass) {
      const action = run ? 'run' : nameTransition ? 'name' : nestedPass ? 'nested-pass' : 'pass';
      const name = run ? run[1] : nameTransition ? nameTransition[1] : nestedPass ? nestedPass[1] : pass[1];
      const expected = timeline[cursor];
      if (!expected || expected[0] !== action || expected[1] !== name) throw new Error('selected test lifecycle/order mismatch');
      cursor++;
      if (action === 'run' && (name === QUERY_CHILD || name === RESTART_CHILD)) pendingNested.push(name);
      if (action === 'nested-pass') {
        if (pendingNested[0] !== name) throw new Error('nested test completion is not pending in measured order');
        pendingNested.shift();
      }
      continue;
    }
    if (line === 'PASS') {
      if (cursor !== timeline.length - 1) throw new Error('package PASS before complete selected tests');
      packagePassed = true;
      cursor++;
      continue;
    }
    if (/^\s*(?:===|---)/.test(line)) throw new Error('malformed or unexpected test lifecycle event');
    if (/^(?:PASS|ok|FAIL)(?:\s|$)/.test(line) || /^=== (?:CONT|PAUSE)/.test(line)) throw new Error('unexpected package or test lifecycle');
    if (line.includes('boundary pass:')) {
      const match = line.match(/^\s*(?:[^\r\n]*?:\d+:\s*)?boundary pass: ([a-z][a-z0-9_]*)\s*$/);
      if (!match) throw new Error('malformed boundary observation');
      const expected = timeline[cursor];
      if (!expected || expected[0] !== 'marker' || match[1] !== expected[2]) throw new Error('boundary phase/order/owner mismatch');
      // Marker ownership is the active lifecycle cursor; source-file/line is
      // deliberately not used because t.Helper attribution is not stable.
      cursor++;
      continue;
    }
    if (/^--- [A-Z]+:/.test(line)) throw new Error('unexpected test lifecycle event');
  }
  if (!started || !packagePassed || cursor !== timeline.length || pendingNested.length !== 0) throw new Error('incomplete selected test transcript');
  return {events:27, selectedTests:2, nestedPhases:2};
}

function buildWslArgv(args) { return ['-d','Ubuntu','-u','berd','--exec',...args]; }
function invokeWsl(args,options={},invoke=spawnSync) { return invoke('wsl.exe',buildWslArgv(args),{cwd:root,encoding:'utf8',windowsHide:true,...options}); }
function shellQuote(value) { return `'${String(value).replaceAll("'","'\\''")}'`; }
function buildBashArgs(repo, command) { return ['bash','--noprofile','--norc','-lc',`cd -- ${shellQuote(repo)} && ${command}`]; }
function assertWslArgv(actual, args) { assert.deepEqual(actual, ['-d','Ubuntu','-u','berd','--exec',...args]); }
function selfTestWslTransport() {
  const windows = String.raw`E:\Anti Gravity\O'Brien\repo`;
  const mapped = "/mnt/e/Anti Gravity/O'Brien/repo";
  let captured;
  const conversion = invokeWsl(['wslpath','-a',windows],{},(program,args,opts)=>{captured={program,args,opts};return {status:0,stdout:`${mapped}\n`,stderr:''};});
  assert.equal(conversion.status,0);
  assert.equal(captured.program,'wsl.exe');
  assertWslArgv(captured.args,['wslpath','-a',windows]);
  assert.equal(conversion.stdout.trim(),mapped);
  const quoted = shellQuote(mapped);
  const cmd = buildBashArgs(mapped,'exec env -i PATH=/usr/bin:/bin HOME=/home/berd LANG=C LC_ALL=C /tmp/boundary.test -test.count=1 -test.timeout=120s -test.run=^(A|B)$');
  assert.deepEqual(cmd,['bash','--noprofile','--norc','-lc',`cd -- ${quoted} && exec env -i PATH=/usr/bin:/bin HOME=/home/berd LANG=C LC_ALL=C /tmp/boundary.test -test.count=1 -test.timeout=120s -test.run=^(A|B)$`]);
  assert(cmd[4].includes("O'\\''Brien"));
  const actual = invokeWsl(cmd,{},(program,args)=>{captured={program,args};return {status:0,stdout:'',stderr:''};});
  assert.equal(actual.status,0);
  assert.equal(captured.program,'wsl.exe');
  assertWslArgv(captured.args,cmd);
  const badVectors = [
    ['-d','Ubuntu','-u','berd','--','wslpath','-a',windows],
    ['-d','Ubuntu','-u','berd','--exec','wslpath',windows],
    ['-d','Ubuntu','-u','berd','--exec','wslpath','-a'],
    ['-d','Ubuntu','-u','berd','--exec','wslpath',`-a${windows}`],
    ['-d','Ubuntu','-u','berd','--exec',`wslpath -a ${windows}`],
  ];
  for (const vector of badVectors) assert.throws(()=>assertWslArgv(vector,['wslpath','-a',windows]));
  assert.throws(()=>assert.deepEqual(buildBashArgs(mapped,'test'),['bash','-lc','cd -- /mnt/e/Anti Gravity/O\'Brien/repo && test']));
}

function runMappingThenFinally(results,removeResult=true,mapper=workspaceWslPaths) {
  const custody={confirmed:true};
  const removed=[];
  let index=0;
  let mappingFailed=false;
  let finalizerFailed=false;
  const runner=()=>results[index++];
  try { mapper(custody,runner); }
  catch { mappingFailed=true; }
  const finalized=finalizeWorkspace('private-temp','private-identity',custody,(temp,identity,confirmed)=>{
    removed.push({temp,identity,confirmed});
    return removeResult;
  });
  try { requireFinalizerSuccess(finalized,custody.confirmed); }
  catch { finalizerFailed=true; }
  return {custody,removed,calls:index,finalized,mappingFailed,finalizerFailed};
}
function assertUncertainMappingFailed(outcome,label) {
  assert.equal(outcome.mappingFailed,true,`${label} did not fail mapping before finalization`);
  assert.equal(outcome.removed.length,0,`${label} invoked workspace removal`);
}
function selfTestWslPathCustody() {
  const good=(stdout='/mnt/e/workspace')=>({status:0,signal:null,error:null,stdout,stderr:''});
  const success=runMappingThenFinally([good(),good('/tmp/api.test')]);
  assert.equal(success.calls,2);
  assert.equal(success.custody.confirmed,true);
  assert.equal(success.removed.length,1,'confirmed mapping/finally must reach exact cleanup callback');
  assert.equal(success.removed[0].confirmed,true);
  assert.equal(success.mappingFailed,false,'known-good mappings must not fail mapping');
  assert.equal(success.finalizerFailed,false,'known-good cleanup must not fail');
  requireFinalizerSuccess(true,true);
  const cleanupNotRemoved=runMappingThenFinally([good(),good('/tmp/api.test')],false);
  assert.equal(cleanupNotRemoved.custody.confirmed,true);
  assert.equal(cleanupNotRemoved.finalized,false);
  assert.equal(cleanupNotRemoved.mappingFailed,false,'cleanup failure is distinct from mapping failure');
  assert.equal(cleanupNotRemoved.finalizerFailed,true,'failed finalizer cannot fall through to success');
  assert.throws(()=>requireFinalizerSuccess(false,true));
  assert.throws(()=>requireFinalizerSuccess(false,false));

  const completedNonzero=runMappingThenFinally([{status:1,signal:null,error:null,stdout:'',stderr:'bounded failure'}]);
  assert.equal(completedNonzero.calls,1);
  assert.equal(completedNonzero.custody.confirmed,true,'a fully reaped nonzero mapper is terminal with captured pipes');
  assert.equal(completedNonzero.removed.length,1);
  assert.equal(completedNonzero.mappingFailed,true,'confirmed nonzero result remains a mapping failure');
  assert.equal(completedNonzero.finalizerFailed,false,'confirmed nonzero result remains cleanup-eligible');

  const noChild=runMappingThenFinally([{status:null,signal:null,error:Object.assign(new Error('not found'),{code:'ENOENT'}),stdout:'',stderr:''}]);
  assert.equal(noChild.custody.confirmed,true,'known ENOENT proves no mapping child started');
  assert.equal(noChild.removed.length,1);
  assert.equal(noChild.mappingFailed,true,'known no-child mapping failure cannot produce success');
  assert.equal(noChild.finalizerFailed,false,'known no-child result remains cleanup-eligible');

  const uncertain=[
    ['first status-zero signal',[{status:0,signal:'SIGTERM',error:null,stdout:'/mnt/e/workspace',stderr:''}]],
    ['first missing stdout',[{status:0,signal:null,error:null,stderr:''}]],
    ['first missing stderr',[{status:0,signal:null,error:null,stdout:'/mnt/e/workspace'}]],
    ['first unknown metadata',[{status:0,signal:null,error:null,stdout:'/mnt/e/workspace',stderr:'',unrecognized:true}]],
    ['first unreadable metadata',[new Proxy({}, {ownKeys(){throw new Error('opaque');}})]],
    ['first prior error',[{status:0,signal:null,error:Object.assign(new Error('prior'),{code:'EIO'}),stdout:'/mnt/e/workspace',stderr:''}]],
    ['second status-zero signal',[good(),{status:0,signal:'SIGTERM',error:null,stdout:'/mnt/e/workspace',stderr:''}]],
    ['second missing stdout',[good(),{status:0,signal:null,error:null,stderr:''}]],
    ['second missing stderr',[good(),{status:0,signal:null,error:null,stdout:'/mnt/e/workspace'}]],
    ['second unknown metadata',[good(),{status:0,signal:null,error:null,stdout:'/mnt/e/workspace',stderr:'',unrecognized:true}]],
    ['second unreadable metadata',[good(),new Proxy({}, {ownKeys(){throw new Error('opaque');}})]],
    ['second prior error',[good(),{status:0,signal:null,error:Object.assign(new Error('prior'),{code:'EIO'}),stdout:'/mnt/e/workspace',stderr:''}]],
    ['first timeout',[{status:null,signal:null,error:Object.assign(new Error('timeout'),{code:'ETIMEDOUT'})}]],
    ['first status-null',[{status:null,signal:null,error:null}]],
    ['first spawn error',[{status:null,signal:null,error:Object.assign(new Error('spawn'),{code:'EIO'})}]],
    ['first output bound',[{status:null,signal:null,error:Object.assign(new Error('output bound'),{code:'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'})}]],
    ['first signal',[{status:null,signal:'SIGTERM',error:null,stdout:'',stderr:''}]],
    ['second timeout',[good(),{status:null,signal:null,error:Object.assign(new Error('timeout'),{code:'ETIMEDOUT'})}]],
    ['second status-null',[good(),{status:null,signal:null,error:null}]],
    ['second spawn error',[good(),{status:null,signal:null,error:Object.assign(new Error('spawn'),{code:'EIO'})}]],
    ['second output bound',[good(),{status:null,signal:null,error:Object.assign(new Error('output bound'),{code:'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'})}]],
    ['second signal',[good(),{status:null,signal:'SIGKILL',error:null,stdout:'',stderr:''}]],
  ];
  for (const [label,results] of uncertain) {
    const outcome=runMappingThenFinally(results);
    assert.equal(outcome.custody.confirmed,false,`${label} uncertainty did not reach shared custody`);
    assertUncertainMappingFailed(outcome,label);
    assert.equal(outcome.finalized,false,`${label} uncertainty reported cleanup`);
    assert.equal(outcome.finalizerFailed,true,`${label} uncertainty must independently fail finalization`);
  }
  const continuedAfterFalseCustody=runMappingThenFinally(
    [{status:0,signal:'SIGTERM',error:null,stdout:'/mnt/e/workspace',stderr:''}],
    true,
    (custody,runner)=>{
      runner();
      custody.confirmed=false;
      return {repoLinux:'/mnt/e/workspace',binaryLinux:'/tmp/api.test'};
    },
  );
  assert.equal(continuedAfterFalseCustody.mappingFailed,false,'negative mutant must model continued mapping');
  assert.equal(continuedAfterFalseCustody.finalizerFailed,true,'negative mutant is rejected later by finalization');
  assert.equal(continuedAfterFalseCustody.removed.length,0,'negative mutant must retain workspace');
  assert.throws(()=>assertUncertainMappingFailed(continuedAfterFalseCustody,'continue-after-false-custody mutant'),
    undefined,'mapping failure oracle must independently reject continuation');
}

function unitSource(source) {
  const start=source.indexOf('\nfunction unitMode() {');
  const end=source.indexOf('\n}\n\nconst args=',start+1);
  assert(start>=0&&end>start,'bounded unit branch is absent');
  return source.slice(start,end+2);
}
function assertUnitWiring(source) {
  const unit=unitSource(source);
  const cleanupStart=source.indexOf('\nfunction cleanupEligible(');
  const cleanupEnd=source.indexOf('\nfunction verifyOwnedTree(',cleanupStart+1);
  assert(cleanupStart>=0&&cleanupEnd>cleanupStart,'custody eligibility predicate is absent');
  const cleanup=source.slice(cleanupStart,cleanupEnd);
  const mustContain=[
    "if (process.platform!=='win32')",
    'verifySourcePins();',
    'sha256(goBytes)!==TOOLCHAIN_SHA256',
    "invokeWsl(['id','-u']",
    "spawnSync(goExe,['test','-c','-o',binary,'./internal/api']",
    "invokeWsl(['chmod','0700',binaryLinux]",
    'buildBashArgs(repoLinux,`exec ${command}`)',
    'invokeWsl(args,{timeout:140000,maxBuffer:4*1024*1024})',
    'const cleanupCustody={confirmed:true}',
    'workspaceWslPaths(cleanupCustody,invokeWsl,root,binary)',
    'finalizeWorkspace(temp,identity,cleanupCustody)',
    'requireFinalizerSuccess(removed,cleanupCustody.confirmed)',
    'timeout --signal=TERM --kill-after=5s 120s env -i',
    '-test.count=1 -test.timeout=120s -test.run=',
    'reduceEvents(parseVerboseOutput(result.stdout))',
  ];
  for (const needle of mustContain) assert(unit.includes(needle),'bounded unit source wiring changed');
  assert(source.includes("  let mappingHasCustody=false;\n  try { mappingHasCustody=wslMappingResultHasCustody(result); }\n  catch { mappingHasCustody=false; }\n  if (!mappingHasCustody) {\n    custody.confirmed=false;\n    throw new Error('WSL path mapping failed; details suppressed');\n  }"),'uncertain WSL mapping must fail immediately');
  assert(source.includes("function requireFinalizerSuccess(removed,confirmed) {\n  if (!removed) throw new Error(confirmed ? 'private workspace identity changed; workspace retained' : 'private workspace custody uncertain; workspace retained');\n}"),'failed finalizer must block success for either custody state');
  assert(unit.includes('  } finally {\n    const removed=finalizeWorkspace(temp,identity,cleanupCustody);\n    requireFinalizerSuccess(removed,cleanupCustody.confirmed);\n  }'),'unit success requires finalizer success regardless of custody outcome');
  assert(cleanup.includes('terminal === true && pipesClosed === true && identityStable === true && exactPrivateRoot === true && allowlistedTree === true'),'custody cleanup guard weakened');
  assert(unit.indexOf('verifySourcePins();')<unit.indexOf('fs.mkdtempSync('),'source pins must be checked before temporary workspace creation');
  assert(unit.indexOf('reduceEvents(parseVerboseOutput(result.stdout))')<unit.indexOf('finalizeWorkspace(temp,identity,cleanupCustody)'),'test parsing must finish before cleanup is authorized');
  assert(unit.indexOf('requireFinalizerSuccess(removed,cleanupCustody.confirmed)')<unit.indexOf("console.log('signed controller node boundary regression passed')"),'success output must follow confirmed cleanup');
  assert(unit.includes('workspaceWslPaths(cleanupCustody,invokeWsl,root,binary)')&&unit.includes('finalizeWorkspace(temp,identity,cleanupCustody)'),'both temporary-workspace WSL path mappings must share finally custody');
  assert(!unit.includes('verify-controller-residency-adapter.mjs'),'legacy broad verifier must not be invoked');
  return true;
}
function selfTestUnitWiring() {
  const source=readBounded('scripts/verify-controller-residency-signed-boundary.mjs').toString('utf8');
  assertUnitWiring(source);
  const replaceLast=(text,needle,replacement)=>{
    const index=text.lastIndexOf(needle);
    assert(index>=0,'source mutant anchor missing');
    return text.slice(0,index)+replacement+text.slice(index+needle.length);
  };
  const missingTimeout=source.replaceAll('timeout --signal=TERM --kill-after=5s 120s env -i','timeout 120s env -i');
  assert.throws(()=>assertUnitWiring(missingTimeout),undefined,'missing inner timeout accepted');
  const missingJoin=source.replaceAll('reduceEvents(parseVerboseOutput(result.stdout))','/* omitted transcript join */');
  assert.throws(()=>assertUnitWiring(missingJoin),undefined,'missing event parser/join accepted');
  const missingCleanup=source.replaceAll('finalizeWorkspace(temp,identity,cleanupCustody)','void temp');
  assert.throws(()=>assertUnitWiring(missingCleanup),undefined,'missing custody cleanup path accepted');
  const missingMappingCustody=source.replaceAll('workspaceWslPaths(cleanupCustody,invokeWsl,root,binary)','workspaceWslPaths({confirmed:true},invokeWsl,root,binary)');
  assert.throws(()=>assertUnitWiring(missingMappingCustody),undefined,'mapping results disconnected from shared finally custody');
  const missingImmediateFailure=replaceLast(source,"  if (!mappingHasCustody) {\n    custody.confirmed=false;\n    throw new Error('WSL path mapping failed; details suppressed');\n  }","  if (!mappingHasCustody) custody.confirmed=false;");
  assert.throws(()=>assertUnitWiring(missingImmediateFailure),undefined,'uncertain mapping allowed to continue');
  const successWithUncertainCustody=replaceLast(source,"function requireFinalizerSuccess(removed,confirmed) {\n  if (!removed) throw new Error(confirmed ? 'private workspace identity changed; workspace retained' : 'private workspace custody uncertain; workspace retained');\n}","function requireFinalizerSuccess(removed,confirmed) {\n  if (!removed && confirmed) throw new Error('private workspace identity changed; workspace retained');\n}");
  assert.throws(()=>assertUnitWiring(successWithUncertainCustody),undefined,'success reachable after finalizer fails with uncertain custody');
  const successBeforeFinalizer=replaceLast(source,'    requireFinalizerSuccess(removed,cleanupCustody.confirmed);','    console.log(\'signed controller node boundary regression passed\');\n    requireFinalizerSuccess(removed,cleanupCustody.confirmed);');
  assert.throws(()=>assertUnitWiring(successBeforeFinalizer),undefined,'success output before finalizer result accepted');
  const broadened=source.replaceAll('terminal === true && pipesClosed === true && identityStable === true && exactPrivateRoot === true && allowlistedTree === true','terminal === true');
  assert.throws(()=>assertUnitWiring(broadened),undefined,'weakened cleanup predicate accepted');
}

function selfTestTranscriptControls() {
  const baseline = expectedTranscript();
  assert.deepEqual(reduceEvents(parseVerboseOutput(verboseTranscript(baseline))),{events:27,selectedTests:2,nestedPhases:2});
  const bad = [];
  const clone=()=>baseline.map((row)=>({...row}));
  const at=(rows,predicate,label)=>{const i=rows.findIndex(predicate);assert(i>=0,`control anchor missing: ${label}`);return i;};
  const move=(rows,from,to)=>{const [row]=rows.splice(from,1);rows.splice(to,0,row);};
  const marker=(name,occurrence=0)=>{const found=baseline.map((row,index)=>({row,index})).filter(({row})=>row.Action==='output'&&row.Output.includes(`boundary pass: ${name}`));assert(found[occurrence],`marker control anchor missing: ${name}/${occurrence}`);return found[occurrence].index;};
  const queryRun=(rows)=>at(rows,(row)=>row.Action==='run'&&row.Test===QUERY_CHILD,'query RUN');
  const restartRun=(rows)=>at(rows,(row)=>row.Action==='run'&&row.Test===RESTART_CHILD,'restart RUN');
  const parentPass=(rows)=>at(rows,(row)=>row.Action==='pass'&&row.Test===TOP_RESIDENCY,'parent PASS');
  const queryPass=(rows)=>at(rows,(row)=>row.Action==='nested-pass'&&row.Test===QUERY_CHILD,'query nested PASS');
  const restartPass=(rows)=>at(rows,(row)=>row.Action==='nested-pass'&&row.Test===RESTART_CHILD,'restart nested PASS');
  const nativeRun=(rows)=>at(rows,(row)=>row.Action==='run'&&row.Test===TOP_COMFY,'native RUN');
  const nameIndexes=(rows)=>rows.flatMap((row,index)=>row.Action==='name'?[index]:[]);
  const queryNameIndex=(rows)=>{const i=nameIndexes(rows).find((index)=>rows[index].Test===TOP_RESIDENCY&&queryRun(rows)<index&&index<restartRun(rows));assert(i!==undefined,'query parent NAME anchor missing');return i;};
  const restartNameIndex=(rows)=>{const i=nameIndexes(rows).find((index)=>rows[index].Test===TOP_RESIDENCY&&restartRun(rows)<index&&index<parentPass(rows));assert(i!==undefined,'restart parent NAME anchor missing');return i;};
  const markerIndex=(rows,name,occurrence=0)=>{const found=rows.flatMap((row,index)=>row.Action==='output'&&row.Output.includes(`boundary pass: ${name}`)?[index]:[]);assert(found[occurrence]!==undefined,`marker control anchor missing: ${name}/${occurrence}`);return found[occurrence];};
  const insertLine=(label,line)=>{const rows=clone();rows.splice(2,0,event('output',TOP_RESIDENCY,`${line}\n`));bad.push([label,rows]);};
  assert.equal(nameIndexes(baseline).length,2,'positive transcript must contain exactly two NAME transitions');
  assert(queryRun(baseline)<queryNameIndex(baseline)&&queryNameIndex(baseline)<markerIndex(baseline,queryConfirmations[0]),'positive query NAME is outside its exact attribution slot');
  assert(restartRun(baseline)<restartNameIndex(baseline)&&restartNameIndex(baseline)<markerIndex(baseline,restartConfirmation[0],1),'positive restart NAME is outside its exact attribution slot');

  for (const [label,occurrence] of [['query NAME omitted',0],['restart NAME omitted',1]]) {
    const rows=clone(); const target=nameIndexes(rows)[occurrence]; assert(target!==undefined,'NAME omission anchor missing'); rows.splice(target,1); bad.push([label,rows]);
  }
  const queryNameDuplicate=clone(); const duplicateQueryNameAt=queryNameIndex(queryNameDuplicate); queryNameDuplicate.splice(duplicateQueryNameAt+1,0,{...queryNameDuplicate[duplicateQueryNameAt]});
  assert(queryRun(queryNameDuplicate)<duplicateQueryNameAt&&duplicateQueryNameAt+1<markerIndex(queryNameDuplicate,queryConfirmations[0]),'duplicate query NAME mutant missed its child attribution slot'); bad.push(['duplicate query parent NAME',queryNameDuplicate]);
  const restartNameDuplicate=clone(); const duplicateRestartNameAt=restartNameIndex(restartNameDuplicate); restartNameDuplicate.splice(duplicateRestartNameAt+1,0,{...restartNameDuplicate[duplicateRestartNameAt]});
  assert(restartRun(restartNameDuplicate)<duplicateRestartNameAt&&duplicateRestartNameAt+1<markerIndex(restartNameDuplicate,restartConfirmation[0],1),'duplicate restart NAME mutant missed its child attribution slot'); bad.push(['duplicate restart parent NAME',restartNameDuplicate]);
  const queryNameEarly=clone(); const earlyQueryNameRow=queryNameEarly.splice(queryNameIndex(queryNameEarly),1)[0]; queryNameEarly.splice(queryRun(queryNameEarly),0,earlyQueryNameRow);
  assert(queryNameEarly.findIndex((row)=>row.Action==='name')<queryRun(queryNameEarly),'early query NAME mutant is not before its child RUN'); bad.push(['query parent NAME before child RUN',queryNameEarly]);
  const queryNameLate=clone(); const lateQueryNameRow=queryNameLate.splice(queryNameIndex(queryNameLate),1)[0]; const firstQueryConfirmation=markerIndex(queryNameLate,queryConfirmations[0]); queryNameLate.splice(firstQueryConfirmation+1,0,lateQueryNameRow);
  assert(queryRun(queryNameLate)<firstQueryConfirmation&&firstQueryConfirmation<queryNameLate.findIndex((row)=>row.Action==='name')&&queryNameLate.findIndex((row)=>row.Action==='name')<parentPass(queryNameLate),'late query NAME mutant is not after its first parent confirmation'); bad.push(['query parent NAME after first confirmation',queryNameLate]);
  const restartNameEarly=clone(); const earlyRestartNameRow=restartNameEarly.splice(restartNameIndex(restartNameEarly),1)[0]; restartNameEarly.splice(restartRun(restartNameEarly),0,earlyRestartNameRow);
  assert(restartNameEarly.indexOf(earlyRestartNameRow)<restartRun(restartNameEarly),'early restart NAME mutant is not before its child RUN'); bad.push(['restart parent NAME before child RUN',restartNameEarly]);
  const restartNameLate=clone(); const lateRestartNameRow=restartNameLate.splice(restartNameIndex(restartNameLate),1)[0]; const restartConfirmationAt=markerIndex(restartNameLate,restartConfirmation[0],1); restartNameLate.splice(restartConfirmationAt+1,0,lateRestartNameRow);
  assert(restartRun(restartNameLate)<restartConfirmationAt&&restartConfirmationAt<restartNameLate.indexOf(lateRestartNameRow)&&restartNameLate.indexOf(lateRestartNameRow)<parentPass(restartNameLate),'late restart NAME mutant is not after its parent confirmation'); bad.push(['restart parent NAME after its confirmation',restartNameLate]);
  const queryNameAfterParent=clone(); const displacedQueryName=queryNameAfterParent.splice(queryNameIndex(queryNameAfterParent),1)[0]; queryNameAfterParent.splice(parentPass(queryNameAfterParent)+1,0,displacedQueryName);
  assert(parentPass(queryNameAfterParent)<queryNameAfterParent.indexOf(displacedQueryName),'query NAME-after-parent mutant is not outside the attribution slot'); bad.push(['query parent NAME after parent PASS',queryNameAfterParent]);
  for (const [label,wrongName] of [['query NAME with child name',QUERY_CHILD],['query NAME with native name',TOP_COMFY],['query NAME with foreign name','ForeignBoundaryTest']]) {
    const rows=clone(); const index=queryNameIndex(rows); rows[index].Test=wrongName; assert(queryRun(rows)<index&&index<markerIndex(rows,queryConfirmations[0]),`${label} mutant missed its query NAME slot`); bad.push([label,rows]);
  }
  for (const [label,line] of [
    ['NAME indented',` === NAME  ${TOP_RESIDENCY}`],
    ['NAME has one separator space',`=== NAME ${TOP_RESIDENCY}`],
    ['NAME has three separator spaces',`=== NAME   ${TOP_RESIDENCY}`],
    ['NAME has trailing junk',`=== NAME  ${TOP_RESIDENCY} trailing`],
    ['NAME is malformed',`=== NAME`],
  ]) {
    const rows=clone(); const index=queryNameIndex(rows); rows[index]=event('name-raw',undefined,`${line}\n`); assert(rows[index].Action==='name-raw'&&queryRun(rows)+1===index,`${label} mutant missed the immediate post-query-RUN slot`); bad.push([label,rows]);
  }
  const outsideName=clone(); outsideName.push(event('name',TOP_RESIDENCY)); bad.push(['extra parent NAME outside both attribution slots',outsideName]);

  const primarySwap=clone(); [primarySwap[marker('load_hot')],primarySwap[marker('uncertain_restart_query_first')]]=[primarySwap[marker('uncertain_restart_query_first')],primarySwap[marker('load_hot')]]; bad.push(['primary lifecycle/websocket/recovery order changed',primarySwap]);
  const earlyConfirmation=clone(); move(earlyConfirmation,marker('late_result_reconciled'),queryRun(earlyConfirmation)); bad.push(['query confirmation before its nested RUN',earlyConfirmation]);
  const lateConfirmation=clone(); move(lateConfirmation,marker('late_result_reconciled'),parentPass(lateConfirmation)+1); bad.push(['query confirmation after parent PASS',lateConfirmation]);
  const confirmationBeforeParent=clone();
  const firstRestartMarkerIndex=marker('uncertain_restart_query_first',0);
  const restartRunIndex=restartRun(confirmationBeforeParent);
  const secondRestartMarkerIndex=marker('uncertain_restart_query_first',1);
  const parentPassIndex=parentPass(confirmationBeforeParent);
  const queryMarkerIndexes=(rows)=>queryConfirmations.map((name)=>rows.flatMap((row,index)=>row.Action==='output'&&row.Output.includes(`boundary pass: ${name}`)?[index]:[]));
  const originalQueryMarkerIndexes=queryMarkerIndexes(confirmationBeforeParent);
  assert(firstRestartMarkerIndex<restartRunIndex&&restartRunIndex<secondRestartMarkerIndex&&secondRestartMarkerIndex+1===parentPassIndex,'restart confirmation control anchors are not in the expected baseline order');
  const parentPassRow=confirmationBeforeParent[parentPassIndex];
  const restartConfirmationRow=confirmationBeforeParent[secondRestartMarkerIndex];
  confirmationBeforeParent[parentPassIndex]=restartConfirmationRow;
  confirmationBeforeParent[secondRestartMarkerIndex]=parentPassRow;
  const mutantRestartMarkerIndexes=confirmationBeforeParent.flatMap((row,index)=>row.Action==='output'&&row.Output.includes('boundary pass: uncertain_restart_query_first')?[index]:[]);
  const mutantPrimaryRestartMarkerIndex=mutantRestartMarkerIndexes[0];
  const mutantRestartConfirmationIndex=mutantRestartMarkerIndexes[1];
  const mutantParentPassIndex=parentPass(confirmationBeforeParent);
  assert(mutantPrimaryRestartMarkerIndex===firstRestartMarkerIndex,'restart-confirmation mutation moved the primary lifecycle marker');
  assert(restartRunIndex<mutantParentPassIndex&&mutantParentPassIndex+1===mutantRestartConfirmationIndex,'restart-confirmation mutation is not exactly after restart RUN and immediately before the second confirmation');
  assert.deepEqual(queryMarkerIndexes(confirmationBeforeParent),originalQueryMarkerIndexes,'restart-confirmation mutation moved a query confirmation');
  bad.push(['parent PASS before restart confirmation',confirmationBeforeParent]);
  const queryPassEarly=clone(); move(queryPassEarly,queryPass(queryPassEarly),queryRun(queryPassEarly)+1); bad.push(['nested query PASS before confirmations',queryPassEarly]);
  const queryPassMissing=baseline.filter((row)=>!(row.Action==='nested-pass'&&row.Test===QUERY_CHILD)); bad.push(['missing deferred nested query PASS',queryPassMissing]);
  const restartPassMissing=baseline.filter((row)=>!(row.Action==='nested-pass'&&row.Test===RESTART_CHILD)); bad.push(['missing deferred nested restart PASS',restartPassMissing]);
  const nestedDuplicate=clone(); nestedDuplicate.splice(queryPass(nestedDuplicate),0,{...nestedDuplicate[queryPass(nestedDuplicate)]}); bad.push(['duplicate deferred nested PASS',nestedDuplicate]);
  const nestedReverse=clone(); const queryPassIndex=queryPass(nestedReverse); const restartPassIndex=restartPass(nestedReverse); const queryPassRow=nestedReverse[queryPassIndex]; nestedReverse[queryPassIndex]=nestedReverse[restartPassIndex]; nestedReverse[restartPassIndex]=queryPassRow; bad.push(['deferred nested PASS order reversed',nestedReverse]);
  const nestedWrongIndent=clone(); nestedWrongIndent[queryPass(nestedWrongIndent)]={...nestedWrongIndent[queryPass(nestedWrongIndent)],Action:'output',Output:`   --- PASS: ${QUERY_CHILD} (0.00s)\n`}; bad.push(['nested PASS wrong indentation',nestedWrongIndent]);
  const nestedWrongName=clone(); nestedWrongName[queryPass(nestedWrongName)].Test=TOP_RESIDENCY; bad.push(['nested PASS wrong name',nestedWrongName]);
  const nestedRunWrongName=clone(); nestedRunWrongName[queryRun(nestedRunWrongName)].Test=TOP_RESIDENCY; bad.push(['nested RUN wrong name',nestedRunWrongName]);
  const nestedUnindented=clone(); nestedUnindented[queryPass(nestedUnindented)].Action='pass'; bad.push(['nested PASS unindented',nestedUnindented]);
  const nestedAfterNative=clone(); const q=nestedAfterNative.splice(queryPass(nestedAfterNative),1)[0]; const r=nestedAfterNative.splice(restartPass(nestedAfterNative),1)[0]; const n=nativeRun(nestedAfterNative); nestedAfterNative.splice(n+1,0,q,r); bad.push(['nested PASS deferred beyond native RUN',nestedAfterNative]);
  const comfySwap=clone(); [comfySwap[marker(comfyEvents[0])],comfySwap[marker(comfyEvents[1])]]=[comfySwap[marker(comfyEvents[1])],comfySwap[marker(comfyEvents[0])]]; bad.push(['native observations reordered',comfySwap]);
  const omitted=baseline.filter((row)=>!(row.Action==='output'&&row.Output.includes('boundary pass: offline_rejected'))); bad.push(['missing primary marker',omitted]);
  const duplicate=clone(); duplicate.splice(marker('warm_verified'),0,event('output',TOP_RESIDENCY,'    node_commands_test.go:1: boundary pass: warm_verified\n')); bad.push(['duplicate marker',duplicate]);
  const unexpected=clone(); unexpected.splice(2,0,event('output',TOP_RESIDENCY,'    node_commands_test.go:1: boundary pass: unauthorized_event\n')); bad.push(['unexpected marker',unexpected]);
  const wrongOwner=clone(); const movedOwner=wrongOwner.splice(marker('node_handle_replay_exact'),1)[0]; wrongOwner.splice(nativeRun(wrongOwner)+1,0,movedOwner); bad.push(['marker moved into wrong top-test phase',wrongOwner]);
  const malformed=clone(); malformed[marker('warm_verified')].Output='boundary pass: warm_verified private-secret\n'; bad.push(['malformed marker',malformed]);
  const premature=clone(); const packagePass=at(premature,(row)=>row.Action==='pass'&&row.Test===undefined,'package PASS'); move(premature,packagePass,parentPass(premature)+1); bad.push(['premature package PASS',premature]);
  bad.push(['missing package PASS',baseline.filter((row)=>!(row.Action==='pass'&&row.Test===undefined))]);
  for (const [label,line] of [
    ['unindented selected FAIL',`--- FAIL: ${TOP_RESIDENCY} (0.00s)`],
    ['indented nested FAIL',`    --- FAIL: ${QUERY_CHILD} (0.00s)`],
    ['unindented selected SKIP',`--- SKIP: ${TOP_RESIDENCY} (0.00s)`],
    ['indented nested SKIP',`    --- SKIP: ${RESTART_CHILD} (0.00s)`],
    ['malformed FAIL lifecycle','--- FAIL:'],
    ['malformed SKIP lifecycle','    --- SKIP:'],
    ['indented RUN lifecycle',`  === RUN   ${TOP_RESIDENCY}`],
    ['indented top PASS lifecycle',` --- PASS: ${TOP_RESIDENCY} (0.00s)`],
    ['malformed RUN lifecycle','=== RUN'],
    ['wrongly indented nested PASS',`     --- PASS: ${QUERY_CHILD} (0.00s)`],
    ['unindented nested PASS',`--- PASS: ${QUERY_CHILD} (0.00s)`],
    ['malformed PASS lifecycle',`    --- PASS: ${QUERY_CHILD}`],
  ]) insertLine(label,line);
  for (const [label, rows] of bad) assert.throws(()=>reduceEvents(parseVerboseOutput(verboseTranscript(rows))),undefined,label);
  assert.throws(()=>reduceEvents(parseVerboseOutput('nope\n')));
  assert.throws(()=>parseVerboseOutput(`=== RUN   ${TOP_RESIDENCY}\n${'x'.repeat(17*1024)}\n`));
  assert.throws(()=>parseVerboseOutput(' '.repeat(4*1024*1024+1)));
  const secret='private-test-output-secret';
  assert.throws(()=>reduceEvents(parseVerboseOutput(verboseTranscript([...baseline,event('output',TOP_COMFY,`boundary pass: bad ${secret}\n`)]))));
  assert.equal(JSON.stringify({status:0,parsed:reduceEvents(parseVerboseOutput(verboseTranscript(baseline)))}).includes(secret),false);
  assert.equal(cleanupEligible({terminal:true,pipesClosed:true,identityStable:true,exactPrivateRoot:true,allowlistedTree:true}),true);
  for (const field of ['terminal','pipesClosed','identityStable','exactPrivateRoot','allowlistedTree']) {
    assert.equal(cleanupEligible({terminal:true,pipesClosed:true,identityStable:true,exactPrivateRoot:true,allowlistedTree:true,[field]:false}),false,`cleanup ${field} mutation accepted`);
  }
}

function sourceMode() {
  selfTestTranscriptControls();
  selfTestWslTransport();
  selfTestWslPathCustody();
  selfTestUnitWiring();
  console.log('signed boundary pure parser, argv, and custody controls passed; source pin currentness follows');
  sourceContracts();
  console.log('signed boundary source controls passed');
}

function runBounded(program,args,options={}) {
  const result = spawnSync(program,args,{cwd:root,encoding:'utf8',windowsHide:true,maxBuffer:4*1024*1024,...options});
  if (result.error || result.status !== 0 || result.signal) throw new Error('bounded verifier command failed; details suppressed');
  return result.stdout ?? '';
}
function verifyGoVersion(goExe) {
  const output = runBounded(goExe,['version'],{timeout:10000,maxBuffer:4096});
  if (output.trim() !== 'go version go1.23.4 windows/amd64') throw new Error('cached Go toolchain identity mismatch');
}
function wslMappingResultHasCustody(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result) || Object.getPrototypeOf(result) !== Object.prototype) return false;
  const knownKeys = new Set(['pid','output','stdout','stderr','status','signal','error']);
  if (Object.keys(result).some((key) => !knownKeys.has(key))) return false;
  if (!['status','signal','stdout','stderr'].every((key) => Object.hasOwn(result,key)) ||
      typeof result.stdout !== 'string' || typeof result.stderr !== 'string') return false;
  if (result.error !== undefined && result.error !== null) return result.error.code === 'ENOENT' && result.status === null && result.signal == null;
  return Number.isInteger(result.status) && result.signal == null;
}
function wslPath(localPath,custody,runner=invokeWsl) {
  let result;
  try { result = runner(['wslpath','-a',localPath],{timeout:10000,maxBuffer:4096}); }
  catch { custody.confirmed=false; throw new Error('WSL path mapping failed; details suppressed'); }
  let mappingHasCustody=false;
  try { mappingHasCustody=wslMappingResultHasCustody(result); }
  catch { mappingHasCustody=false; }
  if (!mappingHasCustody) {
    custody.confirmed=false;
    throw new Error('WSL path mapping failed; details suppressed');
  }
  if (!result || result.error || result.status !== 0 || typeof result.stdout !== 'string') throw new Error('WSL path mapping failed; details suppressed');
  const mapped = result.stdout.trim();
  if (!mapped.startsWith('/') || /[\0\r\n]/.test(mapped)) throw new Error('WSL path mapping was not canonical');
  return mapped;
}
function workspaceWslPaths(custody,runner=invokeWsl,repo=root,binary=path.join(root,'api-linux.test')) {
  const repoLinux=wslPath(repo,custody,runner);
  const binaryLinux=wslPath(binary,custody,runner);
  return {repoLinux,binaryLinux};
}
function directoryIdentity(filename) {
  const info=fs.lstatSync(filename);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('private workspace identity invalid');
  return {dev:info.dev,ino:info.ino,mode:info.mode,birthtimeMs:info.birthtimeMs};
}
function sameDirectoryIdentity(filename,expected) {
  const current=directoryIdentity(filename);
  return current.dev===expected.dev&&current.ino===expected.ino&&current.mode===expected.mode&&current.birthtimeMs===expected.birthtimeMs;
}
function cleanupEligible({terminal, pipesClosed, identityStable, exactPrivateRoot, allowlistedTree}) {
  return terminal === true && pipesClosed === true && identityStable === true && exactPrivateRoot === true && allowlistedTree === true;
}
function verifyOwnedTree(temp) {
  const allowedRootNames = new Set(['api-linux.test','go-cache','go-tmp']);
  let entries = 0;
  function visit(directory, atRoot = false) {
    for (const entry of fs.readdirSync(directory,{withFileTypes:true})) {
      entries++;
      if (entries > 100000) return false;
      const absolute=path.join(directory,entry.name);
      const stat=fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) return false;
      if (atRoot && !allowedRootNames.has(entry.name)) return false;
      if (stat.isDirectory()) { if (!visit(absolute,false)) return false; }
      else if (!stat.isFile()) return false;
    }
    return true;
  }
  return visit(temp,true);
}
function removeOwnedWorkspace(temp,identity,confirmed) {
  const exactPrivateRoot=path.dirname(temp)===os.tmpdir()&&path.basename(temp).startsWith('signed-boundary-verifier-');
  const identityStable=fs.existsSync(temp)&&sameDirectoryIdentity(temp,identity);
  const allowlistedTree=identityStable&&verifyOwnedTree(temp);
  if (!cleanupEligible({terminal:confirmed,pipesClosed:confirmed,identityStable,exactPrivateRoot,allowlistedTree})) return false;
  fs.rmSync(temp,{recursive:true,force:false});
  return !fs.existsSync(temp);
}
function finalizeWorkspace(temp,identity,custody,remove=removeOwnedWorkspace) {
  if (custody?.confirmed !== true) return false;
  return remove(temp,identity,true);
}
function requireFinalizerSuccess(removed,confirmed) {
  if (!removed) throw new Error(confirmed ? 'private workspace identity changed; workspace retained' : 'private workspace custody uncertain; workspace retained');
}
function unitMode() {
  if (process.platform!=='win32') throw new Error('--unit requires Windows with the fixed Ubuntu WSL distribution');
  verifySourcePins();
  const goExe=path.resolve(root,TOOLCHAIN_REL);
  const goBytes=fs.readFileSync(goExe);
  if (sha256(goBytes)!==TOOLCHAIN_SHA256) throw new Error('cached Go executable pin mismatch');
  verifyGoVersion(goExe);
  const wslUid=invokeWsl(['id','-u'],{timeout:10000,maxBuffer:4096});
  if (wslUid.error||wslUid.status!==0||wslUid.stdout.trim()!=='1000') throw new Error('fixed Ubuntu user is not UID 1000');
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'signed-boundary-verifier-'));
  const identity=directoryIdentity(temp);
  const binary=path.join(temp,'api-linux.test');
  const cache=path.join(temp,'go-cache');
  const tmp=path.join(temp,'go-tmp');
  fs.mkdirSync(cache); fs.mkdirSync(tmp);
  const cleanupCustody={confirmed:true};
  try {
    const systemRoot=process.env.SystemRoot??process.env.WINDIR;
    if (!systemRoot) throw new Error('Windows system root is unavailable');
    const env={SystemRoot:systemRoot,WINDIR:systemRoot,TEMP:temp,TMP:temp,PATH:path.join(systemRoot,'System32'),
      GOOS:'linux',GOARCH:'amd64',GOAMD64:'v1',CGO_ENABLED:'0',GOTOOLCHAIN:'local',GOENV:'off',GOWORK:'off',GOFLAGS:'',
      GOPATH:path.join(root,'.cache','gopath'),GOMODCACHE:path.join(root,'.cache','gopath','pkg','mod'),GOPROXY:'off',GOSUMDB:'off',
      GOVCS:'*:off',GOCACHE:cache,GOTMPDIR:tmp,GOROOT:path.dirname(path.dirname(goExe))};
    const build=spawnSync(goExe,['test','-c','-o',binary,'./internal/api'],{cwd:root,env,encoding:'utf8',windowsHide:true,timeout:120000,maxBuffer:4*1024*1024});
    if (build.status===null&&build.error?.code!=='ENOENT') cleanupCustody.confirmed=false;
    if (build.error||build.status!==0||build.signal) throw new Error('offline Linux API compile failed; private output suppressed');
    if (!fs.existsSync(binary)||!fs.statSync(binary).isFile()) throw new Error('compiled API test binary missing');
    const {repoLinux,binaryLinux}=workspaceWslPaths(cleanupCustody,invokeWsl,root,binary);
    const chmod=invokeWsl(['chmod','0700',binaryLinux],{timeout:10000,maxBuffer:4096});
    if (chmod.status===null&&chmod.error?.code!=='ENOENT') cleanupCustody.confirmed=false;
    if (chmod.error||chmod.status!==0) throw new Error('private test binary permission setup failed');
    const envArgs=['PATH=/usr/bin:/bin','HOME=/home/berd','LANG=C','LC_ALL=C'];
    const command=`timeout --signal=TERM --kill-after=5s 120s env -i ${envArgs.map(shellQuote).join(' ')} ${shellQuote(binaryLinux)} -test.v -test.count=1 -test.timeout=120s -test.run=${shellQuote(`^(${TOP_RESIDENCY}|${TOP_COMFY})$`)}`;
    const args=buildBashArgs(repoLinux,`exec ${command}`);
    const result=invokeWsl(args,{timeout:140000,maxBuffer:4*1024*1024});
    if (result.status===null&&result.error?.code!=='ENOENT') cleanupCustody.confirmed=false;
    if (result.error||result.status!==0||result.signal||typeof result.stdout!=='string') throw new Error('bounded Linux API test execution failed; private output suppressed');
    if ((result.stderr??'').length!==0) throw new Error('bounded Linux API test wrote unexpected stderr; private output suppressed');
    reduceEvents(parseVerboseOutput(result.stdout));
  } finally {
    const removed=finalizeWorkspace(temp,identity,cleanupCustody);
    requireFinalizerSuccess(removed,cleanupCustody.confirmed);
  }
  console.log('signed controller node boundary regression passed');
}

const args=process.argv.slice(2);
if (args.length!==1||!['--source','--unit'].includes(args[0])) {
  console.error('usage: node scripts/verify-controller-residency-signed-boundary.mjs --source|--unit');
  process.exitCode=2;
} else {
  try { if (args[0]==='--source') sourceMode(); else unitMode(); }
  catch (error) { console.error(args[0]==='--source' ? `source control failed: ${error?.message ?? 'unknown'}` : 'signed boundary verification failed; sensitive details suppressed'); process.exitCode=1; }
}
