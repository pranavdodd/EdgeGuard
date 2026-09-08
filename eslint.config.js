import eslint from "@eslint/js";

export default [
  {
    ignores: ["node_modules/**", "dist/**", ".wrangler/**"],
  },
  eslint.configs.recommended,
];
