export type MiniMenuItem = {
  id: string;
  label: string;
  href?: string;
  disabled?: boolean;
};

export type MiniMenuProps = {
  items: MiniMenuItem[];
  activeItem?: string;
  className?: string;
  ariaLabel?: string;
  onItemClick?: (item: MiniMenuItem) => void;
};
