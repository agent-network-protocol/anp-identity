import type {} from "@deepseek-ai/dsh-client-ui-slots";

// The additive navigation slot is absent in older shells; slots.inject waits without blocking the settings page.
declare module "@deepseek-ai/dsh-client-ui-slots" {
  interface SlotMap {
    "settings.nav.icon": { kind: "list"; scope: "root"; owner: { children?: never } };
  }
}
