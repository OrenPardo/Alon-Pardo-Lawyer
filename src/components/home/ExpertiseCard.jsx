'use client';
import Link from 'next/link';
import { useTranslation } from 'react-i18next';

export default function ExpertiseCard({ area }) {
  const { t } = useTranslation();

  return (
    <Link
      href={area.path}
      className="expertise-card p-5 md:p-8 border border-stone-100 hover:border-gold transition-colors group rtl:text-right block relative overflow-hidden flex flex-col h-full"
    >
      <div className="card-icon mb-6 text-gold" dangerouslySetInnerHTML={{ __html: area.icon }} />
      <h3 className="text-xl mb-4">{t(area.titleKey)}</h3>
      <ul className="text-stone-600 text-sm leading-relaxed space-y-1 flex-grow">
        {area.bulletKeys.map((key) => (
          <li key={key}>{t(key)}</li>
        ))}
      </ul>
      <div className="mt-6 flex items-center gap-2 transition-colors">
        <span className="text-stone-500 group-hover:text-gold text-xs uppercase tracking-wide transition-colors">{t('card_next_step')}</span>
        <svg aria-hidden="true" className="w-4 h-4 text-stone-500 group-hover:text-gold rtl:rotate-180 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
        </svg>
      </div>
    </Link>
  );
}
