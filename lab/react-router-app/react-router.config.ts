import type { Config } from "@react-router/dev/config";

export default {
  // Enable experimental RSC (required for vulnerability)
  future: {
    unstable_serverComponents: true,
  },
  ssr: true,
} satisfies Config;
