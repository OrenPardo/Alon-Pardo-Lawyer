'use client';

import { useTranslation } from 'react-i18next';
import { usePathname } from 'next/navigation';
import Link from 'next/link';

export default function Footer() {
  const { t, i18n } = useTranslation();
  const isHe = i18n.language === 'he';
  const pathname = usePathname();


  const policyLinks = [
    { key: 'footer_privacy', href: '/privacy' },
    { key: 'footer_terms', href: '/terms' },
    { key: 'footer_cookies', href: '/cookies' },
    { key: 'footer_disclaimer', href: '/disclaimer' },
    { key: 'footer_accessibility_statement', href: '/accessibility-statement' },
  ];

  return (
    <footer className="py-12 bg-stone-950 text-stone-400 border-t border-stone-800">
      <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center md:items-baseline gap-4 md:gap-8 justify-between">
        {/* Brand + policy links — always visually first (left in LTR, right in RTL) */}
        <div className={`flex flex-col items-center md:items-baseline md:flex-row gap-6 md:gap-8 order-1`}>
          <Link
            href="/"
            onClick={(e) => {
              if (pathname === '/') {
                e.preventDefault();
                window.scrollTo({ top: 0, behavior: 'smooth' });
              }
            }}
            className="text-xl font-bold tracking-tighter text-white whitespace-nowrap"
            dangerouslySetInnerHTML={{ __html: t('brand') }}
          />

          <div className={`uppercase tracking-widest flex flex-col items-center md:flex-row md:flex-wrap gap-2 md:gap-x-6 md:gap-y-2 ${isHe ? 'text-[0.95rem]' : 'text-xs'}`}>
            {policyLinks.map(({ key, href }) => (
              <Link
                key={key}
                href={href}
                className="hover:text-white transition"
              >
                {t(key)}
              </Link>
            ))}
          </div>
        </div>

        {/* Copyright — always visually last (right in LTR, left in RTL) */}
        <div
          className={`uppercase tracking-widest text-center md:text-left rtl:md:text-right order-2 ${isHe ? 'text-[0.85rem]' : 'text-xs'}`}
          dangerouslySetInnerHTML={{ __html: t('footer_copy') }}
        />
      </div>
    </footer>
  );
}
