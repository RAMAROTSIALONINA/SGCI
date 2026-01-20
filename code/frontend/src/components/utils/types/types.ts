import type { ReactNode } from 'react';

export type AnyRecord = Record<string, unknown>;

export type AnyFn<Args extends unknown[] = unknown[], Return = unknown> = (
  ...args: Args
) => Return;

export type WithChildren<Props extends object = AnyRecord> = Props & {
  children?: ReactNode;
};

export type Nullable<Value> = Value | null | undefined;

export type ValueOf<ObjectType> = ObjectType[keyof ObjectType];

export type PartialRecord<Key extends PropertyKey, Value> = Partial<
  Record<Key, Value>
>;

export type Mutable<Type> = { -readonly [Prop in keyof Type]: Type[Prop] };

export type DeepPartial<Type> = {
  [Prop in keyof Type]?: DeepPartial<Type[Prop]>;
};
