import * as React from "react"
import { cn } from "@/lib/utils"

function Card({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("liquid-glass-card rounded-xl overflow-hidden", className)}
      {...props}
    />
  )
}

function CardHeader({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("grid auto-rows-min items-start gap-1 rounded-t-xl px-4 py-3", className)}
      {...props}
    />
  )
}

function CardTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("text-[15px] font-semibold leading-snug", className)}
      {...props}
    />
  )
}

function CardDescription({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("text-[13px]", className)}
      style={{ color: '#6e6e73' }}
      {...props}
    />
  )
}

function CardAction({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("col-start-2 row-span-2 row-start-1 self-start justify-self-end", className)}
      {...props}
    />
  )
}

function CardContent({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("px-4 py-3", className)}
      {...props}
    />
  )
}

function CardFooter({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("flex items-center rounded-b-xl border-t px-4 py-3", className)}
      style={{ borderColor: 'rgba(0,0,0,0.06)', background: 'rgba(0,0,0,0.02)' }}
      {...props}
    />
  )
}

interface VividCardProps extends React.ComponentProps<"div"> {
  gradient?: string;
  shadow?: string;
}

function VividCard({ className, gradient, shadow, style, ...props }: VividCardProps) {
  return (
    <div
      className={cn("vivid-shimmer rounded-2xl overflow-hidden text-white", className)}
      style={{
        background: gradient,
        boxShadow: shadow,
        /* refraction filter gives the "liquid" warp on the gradient surface */
        filter: 'url(#liquid-glass-distort)',
        ...style,
      }}
      {...props}
    />
  )
}

export {
  Card,
  VividCard,
  CardHeader,
  CardFooter,
  CardTitle,
  CardAction,
  CardDescription,
  CardContent,
}
