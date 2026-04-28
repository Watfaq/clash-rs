import * as React from "react"
import { cn } from "@/lib/utils"

const variantStyles: Record<string, string> = {
  default: 'bg-[#0071e3] hover:bg-[#0077ed] text-white',
  primary: 'bg-[#0071e3] hover:bg-[#0077ed] text-white',
  outline: 'border border-black/[0.08] bg-white hover:bg-[#f2f2f7] text-[#1d1d1f]',
  secondary: 'bg-black/[0.06] hover:bg-black/[0.1] text-[#1d1d1f]',
  ghost: 'text-[#6e6e73] hover:text-[#1d1d1f] hover:bg-black/[0.05]',
  destructive: 'bg-red-500 hover:bg-red-600 text-white',
  link: 'text-[#0071e3] underline-offset-4 hover:underline',
}

const sizeStyles: Record<string, string> = {
  default: 'h-8 px-3 text-[15px]',
  xs: 'h-6 px-2 text-xs rounded-md',
  sm: 'h-7 px-2.5 text-[0.8rem]',
  lg: 'h-10 px-4 text-[15px]',
  icon: 'size-8',
  'icon-xs': 'size-6',
  'icon-sm': 'size-7',
  'icon-lg': 'size-9',
}

export const buttonVariants = ({
  variant = 'default',
  size = 'default',
}: { variant?: string; size?: string } = {}) =>
  cn(
    'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none',
    variantStyles[variant] ?? variantStyles.default,
    sizeStyles[size] ?? sizeStyles.default
  )

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: keyof typeof variantStyles;
  size?: keyof typeof sizeStyles;
}

function Button({ className, variant = 'default', size = 'default', type, ...props }: ButtonProps) {
  return (
    <button
      type={type ?? 'button'}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  )
}

export { Button }
