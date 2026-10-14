import React from 'react';

interface FireLogoProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg';
  showText?: boolean;
}

export const FireLogo: React.FC<FireLogoProps> = ({ 
  className = '', 
  size = 'md',
  showText = true 
}) => {
  const iconSizes = {
    sm: 'w-7 h-7',
    md: 'w-8 h-8',
    lg: 'w-10 h-10'
  };

  const textSizes = {
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-xl'
  };

  return (
    <div className={`flex items-center gap-2.5 select-none ${className}`}>
      {/* Minimalist Shield + Flame in Sky Blue & Navy */}
      <div className={`relative flex items-center justify-center shrink-0 ${iconSizes[size]}`}>
        <svg 
          viewBox="0 0 40 44" 
          fill="none" 
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-full"
        >
          {/* Fine Shield Outline */}
          <path 
            d="M20 2L4 7.5V19C4 29 11 38 20 41C29 38 36 29 36 19V7.5L20 2Z" 
            fill="#FFFFFF" 
            stroke="#38A8FF" 
            strokeWidth="2.2" 
            strokeLinejoin="round"
          />
          {/* Stylized Minimal Flame Core */}
          <path 
            d="M20 12C20 12 15.5 17 15.5 21.5C15.5 24 17.5 26 20 26C22.5 26 24.5 24 24.5 21.5C24.5 17 20 12 20 12Z" 
            fill="#38A8FF" 
          />
          <path 
            d="M20 17C20 17 17.8 19.8 17.8 22C17.8 23.2 18.8 24.2 20 24.2C21.2 24.2 22.2 23.2 22.2 22C22.2 19.8 20 17 20 17Z" 
            fill="#E5F3FF" 
          />
        </svg>
      </div>

      {showText && (
        <div className="flex flex-col leading-tight">
          <div className={`font-bold tracking-tight text-[#172B4D] ${textSizes[size]}`}>
            FIRE <span className="text-[#38A8FF]">AGENT</span>
          </div>
          <div className="text-[10px] text-[#718096] font-normal tracking-normal">
            Défense • Analyse • Protection
          </div>
        </div>
      )}
    </div>
  );
};

