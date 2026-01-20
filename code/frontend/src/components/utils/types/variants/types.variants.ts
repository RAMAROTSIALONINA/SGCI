export type VariantMap<Variant extends string, Value = string> = Record<
  Variant,
  Value
>;

export type VariantProps<Variants extends Record<string, unknown>> = {
  [Key in keyof Variants]?: Variants[Key];
};
