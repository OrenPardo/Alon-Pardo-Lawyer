'use client';
import { useTranslation } from 'react-i18next';
import Link from 'next/link';
import ExpertiseCard from './ExpertiseCard';
import { practiceAreas } from '@/data/practiceAreas';

export default function ExpertiseSection() {
  const { t } = useTranslation();

  return (
    <section id="expertise" className="py-12 md:py-24 bg-white">
      <div className="max-w-7xl mx-auto px-6">
        <div className="mb-16 rtl:text-right">
          <h2 className="text-4xl md:text-5xl mb-4">{t('expertise_title')}</h2>
          <p className="text-stone-500 text-lg mb-4">{t('expertise_subtitle')}</p>
          <div className="h-1 w-20 bg-gold rtl:mr-0 rtl:ml-auto" />
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 md:gap-8">
          {practiceAreas.map((area) => (
            <ExpertiseCard key={area.key} area={area} />
          ))}
        </div>
        {/* Helper Block */}
        <div className="mt-16 p-6 bg-stone-50 border border-stone-200 text-center rtl:text-center">
          <h3 className="text-2xl mb-2">{t('helper_title')}</h3>
          <p className="text-stone-600 mb-4 max-w-xl mx-auto">{t('helper_desc')}</p>
          <Link
            href="#contact"
            className="inline-block bg-gold text-white px-8 py-4 font-bold uppercase tracking-widest hover:bg-black border border-gold transition"
          >
            {t('helper_cta')}
          </Link>
          <p className="mt-3 text-stone-600 text-xs flex items-center justify-center gap-1">
            <svg aria-hidden="true" className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
            </svg>
            <span>{t('helper_trust')}</span>
          </p>
        </div>
      </div>
    </section>
  );
}
