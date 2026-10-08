import http from '@/api';
import { ResPage } from '../interface';

export namespace Waf {
    export interface CC {
        enabled: boolean;
        requests: number;
        window: number;
        blockSeconds: number;
    }
    export interface Config {
        enabled: boolean;
        mode: 'block' | 'observe';
        realIpHeader: string;
        ipWhite: string[];
        ipBlack: string[];
        urlWhite: string[];
        urlBlack: string[];
        uaBlack: string[];
        methodWhite: string[];
        disabledHosts: string[];
        cc: CC;
        sqli: boolean;
        xss: boolean;
        traversal: boolean;
        rce: boolean;
        scanner: boolean;
        sensitiveFile: boolean;
        bodyCheck: boolean;
        maxBodyKB: number;
    }
    export interface Status {
        installed: boolean;
        active: boolean;
        config: Config;
    }
    export interface Log {
        time: string;
        ip: string;
        host: string;
        method: string;
        uri: string;
        rule: string;
        match: string;
        action: string;
        ua: string;
        id: string;
    }
    export interface LogSearch {
        page: number;
        pageSize: number;
        ip: string;
        rule: string;
        host: string;
    }
}

export const getWafStatus = () => {
    return http.get<Waf.Status>(`/websites/waf/status`);
};

export const updateWafConfig = (req: Waf.Config) => {
    return http.post(`/websites/waf/update`, req, 60000);
};

export const addWafIP = (ip: string, list: 'white' | 'black') => {
    return http.post(`/websites/waf/ip`, { ip, list }, 60000);
};

export const searchWafLogs = (req: Waf.LogSearch) => {
    return http.post<ResPage<Waf.Log>>(`/websites/waf/logs`, req);
};

export const clearWafLogs = () => {
    return http.post(`/websites/waf/logs/clear`, {});
};
