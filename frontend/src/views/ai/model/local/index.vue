<template>
    <div>
        <el-button class="mt-4" icon="Back" @click="router.push('/ai/model/local')">
            {{ $t('aiTools.model.engines') }}
        </el-button>
        <component :is="currentComponent" v-if="currentComponent" />
    </div>
</template>

<script setup lang="ts">
import { computed, defineAsyncComponent, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import TensorRTView from '@/views/ai/model/tensorrt/index.vue';
import { loadOptionalComponent } from '@/extensions/optional';
import { useGlobalStore } from '@/composables/useGlobalStore';
import { vllmAvailable } from '../deployment';

// Community edition: no vLLM upsell placeholder. vLLM only renders when the
// optional xpack module is actually present; otherwise fall back to the engine list.
const VllmView = defineAsyncComponent(() => loadOptionalComponent('/src/xpack/views/vllm/index.vue'));
const route = useRoute();
const router = useRouter();
const { isFxplay, isProductPro } = useGlobalStore();
const vllmEnabled = computed(() => isProductPro.value && vllmAvailable);
const currentComponent = computed(() => {
    if (route.query.tab === 'vllm' && vllmEnabled.value) return VllmView;
    if (route.query.tab === 'tensorrt' && isFxplay.value) return TensorRTView;
    return null;
});
watch(
    [() => route.query.tab, isFxplay, vllmEnabled],
    async () => {
        const tab = route.query.tab;
        if ((tab === 'tensorrt' && !isFxplay.value) || (tab === 'vllm' && !vllmEnabled.value)) {
            await router.replace('/ai/model/local');
        }
    },
    { immediate: true },
);
</script>
