/// <reference types="vite/client" />

interface ImportMetaEnv {
    readonly VITE_KMS_URL?: string;
    /** Set to "true" at build time to activate DEV unrestricted mode (skips auth, no login screen). */
    readonly VITE_DEV_MODE?: string;
}

interface ImportMeta {
    readonly env: ImportMetaEnv;
}
