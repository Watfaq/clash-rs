import * as React from "react"
import { cn } from "@/lib/utils"

const variantStyles: Record<string, string> = {
  default: 'bg-black/[0.06] text-[#6e6e73]',
  secondary: 'bg-black/[0.06] text-[#6e6e73]',
  destructive: 'bg-[#ff3b30]/10 text-[#ff3b30]',
  outline: 'border border-black/[0.08] text-[#1d1d1f]',
  ghost: 'text-[#6e6e73] hover:bg-black/[0.05]',
  link: 'text-[#0071e3] underline-offset-4 hover:underline',
  blue: 'bg-[#0071e3]/10 text-[#0071e3]',
  green: 'bg-[#34c759]/10 text-[#34c759]',
  amber: 'bg-[#ff9500]/10 text-[#ff9500]',
  violet: 'bg-[#af52de]/10 text-[#af52de]',
  gray: 'bg-black/[0.06] text-[#6e6e73]',
  red: 'bg-[#ff3b30]/10 text-[#ff3b30]',
}

export const badgeVariants = ({ variant = 'default' }: { variant?: string } = {}) =>
  cn(
    'inline-flex items-center text-[11px] font-semibold px-2 py-0.5 rounded-full',
    variantStyles[variant] ?? variantStyles.default
  )

interface BadgeProps extends React.ComponentProps<"span"> {
  variant?: keyof typeof variantStyles;
}

function Badge({ className, variant = 'default', ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center text-[11px] font-semibold px-2 py-0.5 rounded-full',
        variantStyles[variant] ?? variantStyles.default,
        className
      )}
      {...props}
    />
  )
}

export { Badge }
