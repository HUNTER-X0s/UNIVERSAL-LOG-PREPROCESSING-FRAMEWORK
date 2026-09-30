import React from 'react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  icon?: React.ReactNode;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(({
  children,
  variant = 'secondary',
  size = 'md',
  icon,
  className = '',
  disabled,
  ...props
}, ref) => {
  const baseClasses = 'inline-flex items-center justify-center font-medium rounded transition-colors focus:outline-none focus:ring-2 focus:ring-offset-1 focus:ring-gov-blue disabled:opacity-50 disabled:cursor-not-allowed';

  const sizeClasses = {
    sm: 'text-xs px-2.5 py-1 gap-1.5',
    md: 'text-xs px-3.5 py-1.5 gap-2',
    lg: 'text-sm px-4 py-2 gap-2.5',
  }[size];

  const variantClasses = {
    primary: '!bg-gov-blue hover:!bg-gov-dark !text-white shadow-sm border border-transparent',
    secondary: 'bg-white hover:bg-slate-50 text-navy-900 border border-border-medium shadow-sm',
    outline: 'bg-transparent hover:bg-gov-light text-gov-blue border border-gov-border',
    danger: '!bg-red-600 !text-white hover:!bg-red-700 shadow-sm border border-transparent',
    ghost: 'bg-transparent hover:bg-slate-100 text-navy-800',
  }[variant];

  return (
    <button
      ref={ref}
      className={`${baseClasses} ${sizeClasses} ${variantClasses} ${className}`}
      disabled={disabled}
      {...props}
    >
      {icon && <span className="flex-shrink-0">{icon}</span>}
      {children}
    </button>
  );
});

Button.displayName = 'Button';
