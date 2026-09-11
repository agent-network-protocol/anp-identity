import type { Context as ClientContext } from "@deepseek-ai/cordis";
import type {} from "@deepseek-ai/dsh-client-ui-renderer/client";
import type {} from "@deepseek-ai/dsh-api-remotes/client";
import type {} from "@deepseek-ai/dsh-client-ui-layout/client";
import type {} from "@deepseek-ai/dsh-client-ui-settings/client";
import managementRemote from "../remote.js";
import { IdentityController, type ManagementRemote } from "./controller.js";
import { IdentityOverlay, IdentitySettings } from "./views.js";
import { mountStyles } from "./styles.js";
import { IdentityIcon } from "./identity-icon.js";
import type {} from "./settings-icon-slot.js";

export const inject = ["slots", "remote", "connection"];
export async function apply(ctx: ClientContext): Promise<() => Promise<void>> {
  const unmount = await ctx.remote.$mount(managementRemote);
  const disposeStyles = mountStyles();
  const disposers: (() => void)[] = [];
  let controller: IdentityController | undefined;
  try {
    const remote = ctx.get("remote.anpIdentityManager") as unknown as
      ManagementRemote | undefined;
    if (!remote) throw new Error("ANP Identity manager Remote is unavailable");
    controller = new IdentityController(remote);
    const active = controller;
    disposers.push(
      ctx.slots.inject("settings.nav.icon", () =>
        ctx.slots.register({ name: "settings.nav.icon", id: "anp-identity" }, IdentityIcon),
      ),
    );
    disposers.push(
      ctx.slots.inject("settings.section", () =>
        ctx.slots.register(
          {
            name: "settings.section",
            id: "anp-identity",
            label: "身份",
            order: 40,
            inject: () => ({ controller: active }),
          },
          IdentitySettings,
        ),
      ),
    );
    disposers.push(
      ctx.slots.inject("shell.overlay", () =>
        ctx.slots.register(
          {
            name: "shell.overlay",
            id: "anp-identity-authorization",
            order: 50,
            inject: () => ({ controller: active }),
          },
          IdentityOverlay,
        ),
      ),
    );
    active.start();
  } catch (error) {
    controller?.dispose();
    for (const dispose of disposers.reverse()) dispose();
    disposeStyles();
    await unmount();
    throw error;
  }
  return async () => {
    controller?.dispose();
    for (const dispose of disposers.reverse()) dispose();
    disposeStyles();
    await unmount();
  };
}
export { IdentityController, IdentitySettings, IdentityOverlay };
