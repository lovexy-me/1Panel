<template>
    <div>
        <RouterButton :buttons="routerButton" />
        <LayoutContent :title="$t('menu.waf')" v-loading="loading">
            <template #leftToolBar>
                <el-tag :type="status.active ? 'success' : 'info'" class="mr-2">
                    {{ status.active ? $t('waf.running') : $t('waf.stopped') }}
                </el-tag>
                <el-tag v-if="status.active && form.mode === 'observe'" type="warning">{{ $t('waf.observe') }}</el-tag>
            </template>
            <template #main>
                <el-alert v-if="!status.installed" type="warning" :closable="false" :title="$t('waf.noOpenresty')" />
                <el-tabs v-else v-model="tab">
                    <el-tab-pane :label="$t('waf.settings')" name="settings">
                        <el-form :model="form" label-position="left" label-width="160px" class="max-w-4xl">
                            <el-form-item :label="$t('waf.enable')">
                                <el-switch v-model="form.enabled" />
                            </el-form-item>
                            <el-form-item :label="$t('waf.mode')">
                                <el-radio-group v-model="form.mode">
                                    <el-radio value="block">{{ $t('waf.block') }}</el-radio>
                                    <el-radio value="observe">{{ $t('waf.observe') }}</el-radio>
                                </el-radio-group>
                                <span class="input-help">{{ $t('waf.modeHelper') }}</span>
                            </el-form-item>

                            <el-divider content-position="left">{{ $t('waf.attackRules') }}</el-divider>
                            <el-form-item :label="$t('waf.sqli')"><el-switch v-model="form.sqli" /></el-form-item>
                            <el-form-item :label="$t('waf.xss')"><el-switch v-model="form.xss" /></el-form-item>
                            <el-form-item :label="$t('waf.traversal')">
                                <el-switch v-model="form.traversal" />
                            </el-form-item>
                            <el-form-item :label="$t('waf.rce')"><el-switch v-model="form.rce" /></el-form-item>
                            <el-form-item :label="$t('waf.scanner')"><el-switch v-model="form.scanner" /></el-form-item>
                            <el-form-item :label="$t('waf.sensitiveFile')">
                                <el-switch v-model="form.sensitiveFile" />
                            </el-form-item>
                            <el-form-item :label="$t('waf.bodyCheck')">
                                <el-switch v-model="form.bodyCheck" />
                                <el-input-number
                                    v-if="form.bodyCheck"
                                    v-model="form.maxBodyKB"
                                    :min="1"
                                    :max="10240"
                                    class="ml-4"
                                />
                                <span v-if="form.bodyCheck" class="ml-2">KB</span>
                            </el-form-item>

                            <el-divider content-position="left">{{ $t('waf.cc') }}</el-divider>
                            <el-form-item :label="$t('waf.enable')">
                                <el-switch v-model="form.cc.enabled" />
                            </el-form-item>
                            <el-form-item v-if="form.cc.enabled" :label="$t('waf.ccRule')">
                                <el-input-number v-model="form.cc.window" :min="1" :max="86400" />
                                <span class="mx-2">{{ $t('waf.ccSeconds') }}</span>
                                <el-input-number v-model="form.cc.requests" :min="1" :max="1000000" />
                                <span class="mx-2">{{ $t('waf.ccBan') }}</span>
                                <el-input-number v-model="form.cc.blockSeconds" :min="1" :max="2592000" />
                                <span class="ml-2">{{ $t('waf.seconds') }}</span>
                            </el-form-item>

                            <el-divider content-position="left">{{ $t('waf.lists') }}</el-divider>
                            <el-form-item :label="$t('waf.ipWhite')">
                                <el-input
                                    v-model="text.ipWhite"
                                    type="textarea"
                                    :rows="3"
                                    :placeholder="$t('waf.ipHelper')"
                                />
                            </el-form-item>
                            <el-form-item :label="$t('waf.ipBlack')">
                                <el-input
                                    v-model="text.ipBlack"
                                    type="textarea"
                                    :rows="3"
                                    :placeholder="$t('waf.ipHelper')"
                                />
                            </el-form-item>
                            <el-form-item :label="$t('waf.urlWhite')">
                                <el-input
                                    v-model="text.urlWhite"
                                    type="textarea"
                                    :rows="3"
                                    :placeholder="$t('waf.textHelper')"
                                />
                            </el-form-item>
                            <el-form-item :label="$t('waf.urlBlack')">
                                <el-input
                                    v-model="text.urlBlack"
                                    type="textarea"
                                    :rows="3"
                                    :placeholder="$t('waf.textHelper')"
                                />
                            </el-form-item>
                            <el-form-item :label="$t('waf.uaBlack')">
                                <el-input
                                    v-model="text.uaBlack"
                                    type="textarea"
                                    :rows="3"
                                    :placeholder="$t('waf.textHelper')"
                                />
                            </el-form-item>
                            <el-form-item :label="$t('waf.methodWhite')">
                                <el-select v-model="form.methodWhite" multiple class="w-full">
                                    <el-option v-for="m in methods" :key="m" :label="m" :value="m" />
                                </el-select>
                            </el-form-item>
                            <el-form-item :label="$t('waf.disabledHosts')">
                                <el-input
                                    v-model="text.disabledHosts"
                                    type="textarea"
                                    :rows="2"
                                    :placeholder="$t('waf.hostHelper')"
                                />
                            </el-form-item>
                            <el-form-item :label="$t('waf.realIpHeader')">
                                <el-input v-model="form.realIpHeader" placeholder="X-Forwarded-For" class="max-w-xs" />
                                <span class="input-help">{{ $t('waf.realIpHelper') }}</span>
                            </el-form-item>
                            <el-form-item>
                                <el-button type="primary" v-permission :loading="saving" @click="save">
                                    {{ $t('commons.button.save') }}
                                </el-button>
                            </el-form-item>
                        </el-form>
                    </el-tab-pane>

                    <el-tab-pane :label="$t('waf.logs')" name="logs">
                        <div class="flex flex-wrap gap-2 mb-3">
                            <el-input
                                v-model="logQuery.ip"
                                placeholder="IP"
                                clearable
                                class="!w-44"
                                @change="searchLogs"
                            />
                            <el-input
                                v-model="logQuery.host"
                                :placeholder="$t('waf.host')"
                                clearable
                                class="!w-48"
                                @change="searchLogs"
                            />
                            <el-select
                                v-model="logQuery.rule"
                                :placeholder="$t('waf.rule')"
                                clearable
                                class="!w-44"
                                @change="searchLogs"
                            >
                                <el-option v-for="r in ruleNames" :key="r" :label="ruleLabel(r)" :value="r" />
                            </el-select>
                            <el-button @click="searchLogs">{{ $t('commons.button.search') }}</el-button>
                            <el-button type="danger" plain v-permission @click="clearLogs">
                                {{ $t('waf.clearLogs') }}
                            </el-button>
                        </div>
                        <ComplexTable
                            :data="logs"
                            :pagination-config="logPage"
                            @search="searchLogs"
                            v-loading="logLoading"
                        >
                            <el-table-column :label="$t('commons.table.date')" prop="time" width="170px" />
                            <el-table-column label="IP" prop="ip" width="150px" />
                            <el-table-column
                                :label="$t('waf.host')"
                                prop="host"
                                min-width="140px"
                                show-overflow-tooltip
                            />
                            <el-table-column label="URI" min-width="220px" show-overflow-tooltip>
                                <template #default="{ row }">{{ row.method }} {{ row.uri }}</template>
                            </el-table-column>
                            <el-table-column :label="$t('waf.rule')" width="130px">
                                <template #default="{ row }">
                                    <el-tag :type="row.action === 'block' ? 'danger' : 'warning'">
                                        {{ ruleLabel(row.rule) }}
                                    </el-tag>
                                </template>
                            </el-table-column>
                            <el-table-column
                                :label="$t('waf.match')"
                                prop="match"
                                min-width="160px"
                                show-overflow-tooltip
                            />
                            <el-table-column :label="$t('commons.table.operate')" width="120px" fixed="right">
                                <template #default="{ row }">
                                    <el-button link type="primary" v-permission @click="banIP(row.ip)">
                                        {{ $t('waf.ban') }}
                                    </el-button>
                                    <el-button link type="primary" v-permission @click="allowIP(row.ip)">
                                        {{ $t('waf.allow') }}
                                    </el-button>
                                </template>
                            </el-table-column>
                        </ComplexTable>
                    </el-tab-pane>
                </el-tabs>
            </template>
        </LayoutContent>
    </div>
</template>

<script lang="ts" setup>
import { onMounted, reactive, ref, watch } from 'vue';
import { ElMessageBox } from 'element-plus';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';
import { addWafIP, clearWafLogs, getWafStatus, searchWafLogs, updateWafConfig, Waf } from '@/api/modules/waf';

const routerButton = [{ label: i18n.global.t('menu.waf'), path: '/websites/waf' }];
const methods = [
    'GET',
    'POST',
    'HEAD',
    'PUT',
    'DELETE',
    'OPTIONS',
    'PATCH',
    'PROPFIND',
    'PROPPATCH',
    'MKCOL',
    'COPY',
    'MOVE',
    'LOCK',
    'UNLOCK',
];
const ruleNames = [
    'sqli',
    'xss',
    'traversal',
    'rce',
    'scanner',
    'sensitiveFile',
    'cc',
    'ipBlack',
    'urlBlack',
    'uaBlack',
    'method',
];

const loading = ref(false);
const saving = ref(false);
const tab = ref('settings');
const status = reactive({ installed: true, active: false });
const form = reactive<Waf.Config>({
    enabled: false,
    mode: 'block',
    realIpHeader: '',
    ipWhite: [],
    ipBlack: [],
    urlWhite: [],
    urlBlack: [],
    uaBlack: [],
    methodWhite: [],
    disabledHosts: [],
    cc: { enabled: true, requests: 300, window: 60, blockSeconds: 600 },
    sqli: true,
    xss: true,
    traversal: true,
    rce: true,
    scanner: true,
    sensitiveFile: true,
    bodyCheck: true,
    maxBodyKB: 64,
});
const text = reactive({ ipWhite: '', ipBlack: '', urlWhite: '', urlBlack: '', uaBlack: '', disabledHosts: '' });
type ListKey = keyof typeof text;
const listKeys: ListKey[] = ['ipWhite', 'ipBlack', 'urlWhite', 'urlBlack', 'uaBlack', 'disabledHosts'];

const toLines = (v: string) =>
    v
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);

const ruleLabel = (r: string) => {
    const key = 'waf.' + r;
    const label = i18n.global.t(key);
    return label === key ? r : label;
};

const load = async () => {
    loading.value = true;
    try {
        const res = await getWafStatus();
        status.installed = res.data.installed;
        status.active = res.data.active;
        const cfg = res.data.config;
        Object.assign(form, cfg, { cc: { ...form.cc, ...(cfg.cc || {}) } });
        for (const k of listKeys) {
            text[k] = ((cfg as any)[k] || []).join('\n');
        }
    } finally {
        loading.value = false;
    }
};

const save = async () => {
    for (const k of listKeys) {
        (form as any)[k] = toLines(text[k]);
    }
    saving.value = true;
    try {
        await updateWafConfig({ ...form });
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        await load();
    } finally {
        saving.value = false;
    }
};

const logs = ref<Waf.Log[]>([]);
const logLoading = ref(false);
const logQuery = reactive({ ip: '', host: '', rule: '' });
const logPage = reactive({ cacheSizeKey: 'waf-log-page-size', currentPage: 1, pageSize: 20, total: 0 });

const searchLogs = async () => {
    logLoading.value = true;
    try {
        const res = await searchWafLogs({ page: logPage.currentPage, pageSize: logPage.pageSize, ...logQuery });
        logs.value = res.data.items || [];
        logPage.total = res.data.total;
    } finally {
        logLoading.value = false;
    }
};

const clearLogs = async () => {
    await ElMessageBox.confirm(i18n.global.t('waf.clearConfirm'), i18n.global.t('waf.clearLogs'), { type: 'warning' });
    await clearWafLogs();
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
    searchLogs();
};

const changeIP = async (ip: string, list: 'white' | 'black') => {
    await ElMessageBox.confirm(
        `${list === 'black' ? i18n.global.t('waf.ban') : i18n.global.t('waf.allow')}: ${ip}`,
        i18n.global.t('menu.waf'),
        { type: 'warning' },
    );
    await addWafIP(ip, list);
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
    load();
};
const banIP = (ip: string) => changeIP(ip, 'black');
const allowIP = (ip: string) => changeIP(ip, 'white');

watch(tab, (v) => {
    if (v === 'logs') searchLogs();
});

onMounted(load);
</script>
