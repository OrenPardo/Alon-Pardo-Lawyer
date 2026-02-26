'use client';
import { useTranslation } from 'react-i18next';
import Image from 'next/image';
import Link from 'next/link';

export default function HeroSection() {
  const { t, i18n } = useTranslation();
  const isHe = i18n.language === 'he';

  return (
    <section className="relative min-h-screen flex items-center pt-16 md:pt-20 hero-gradient text-white overflow-hidden">
      <div className="absolute right-0 top-0 w-1/3 h-full bg-stone-800/20 skew-x-12 transform translate-x-1/2" />
      <div className="max-w-7xl mx-auto px-6 relative z-10 grid md:grid-cols-2 gap-12 items-center">
        <div className="rtl:text-right">
          <span className={`text-gold uppercase tracking-[0.3em] block ${isHe ? 'text-[1.1rem] mb-2' : 'text-sm mb-4'}`}>
            {t('hero_subtitle')}
          </span>
          <h1 className={`mb-6 ${isHe ? 'text-[2.5rem] sm:text-[3.5rem] md:text-[4.5rem] leading-none' : 'text-3xl sm:text-5xl md:text-7xl leading-tight'}`}>
            {t('hero_title')}
          </h1>
          <p className={`text-stone-400 mb-8 max-w-lg leading-relaxed ${isHe ? 'text-[1.35rem]' : 'text-lg'}`}>
            {t('hero_description')}
          </p>
          <div className="flex flex-col sm:flex-row gap-4">
            <Link
              href="#contact"
              className={`bg-gold text-white px-8 py-4 text-center font-bold uppercase tracking-widest hover:bg-white hover:text-stone-900 transition ${isHe ? 'text-[1.1rem]' : ''}`}
            >
              {t('hero_cta_1')}
            </Link>
            <Link
              href="#expertise"
              className={`border border-stone-500 px-8 py-4 text-center font-bold uppercase tracking-widest hover:bg-white hover:text-stone-900 transition ${isHe ? 'text-[1.1rem]' : ''}`}
            >
              {t('hero_cta_2')}
            </Link>
          </div>
          <p className={`text-stone-400 mt-4 ${isHe ? 'text-[1rem]' : 'text-sm'}`}>{t('hero_cta_note')}</p>
        </div>
        <div className="hidden md:block">
          <div className="relative">
            <div className="absolute -inset-4 border border-gold/30 rounded-sm" />
            <Image
              src="https://images.unsplash.com/photo-1505664194779-8beaceb93744?auto=format&fit=crop&q=80&w=800"
              alt="Legal Professional"
              className="relative grayscale hover:grayscale-0 transition duration-700 shadow-2xl"
              width={800}
              height={534}
              priority
            />
          </div>
        </div>
      </div>
    </section>
  );
}
