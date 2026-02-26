'use client';
import { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import Link from 'next/link';
import { practiceAreas } from '@/data/practiceAreas';

export default function PracticeAreaContent({ areaKey, isPolicy = false }) {
  const { t, i18n } = useTranslation();
  const prefix = areaKey.replace(/-/g, '_');

  const title = t(`${prefix}_title`);
  const desc = t(`${prefix}_desc`);
  const scope = t(`${prefix}_scope`);
  const icon = t(`${prefix}_icon`, { defaultValue: '' });

  // Array fields
  const commonSituations = t(`${prefix}_common_situations`, { returnObjects: true });
  const whatToDo = t(`${prefix}_what_to_do`, { returnObjects: true });
  const howIHelp = t(`${prefix}_how_i_help`, { returnObjects: true });
  const services = t(`${prefix}_services`, { returnObjects: true });

  const commonSituationsTitle = t(`${prefix}_common_situations_title`, { defaultValue: '' });
  const whatToDoTitle = t(`${prefix}_what_to_do_title`, { defaultValue: '' });
  const howIHelpTitle = t(`${prefix}_how_i_help_title`, { defaultValue: '' });
  const servicesLabel = t(`${prefix}_services_label`, { defaultValue: t('services_label') });

  const hasSections = Array.isArray(commonSituations) && commonSituations.length > 0;

  // Sticky bar: anchor menu for policy pages, practice area nav for expertise pages
  const hasAnchors = scope && scope.includes('<a');
  const titleRef = useRef(null);
  const scopeRef = useRef(null);
  const [barStuck, setBarStuck] = useState(false);

  // Observe the scope element (policy) or the h1 title (practice area)
  useEffect(() => {
    const target = hasAnchors ? scopeRef.current : (!isPolicy ? titleRef.current : null);
    if (!target) return;

    const observer = new IntersectionObserver(
      ([entry]) => setBarStuck(!entry.isIntersecting),
      { rootMargin: '-72px 0px 0px 0px' }
    );
    observer.observe(target);
    return () => observer.disconnect();
  }, [hasAnchors, isPolicy, scope]);

  // All practice areas for the sticky nav (current page highlighted)
  const navAreas = isPolicy ? [] : practiceAreas;

  return (
    <main id="main" className="pt-28 pb-12 md:pt-48 md:pb-24">
      {/* Background icon */}
      {!isPolicy && icon && (
        <div className="expertise-bg text-gold" dangerouslySetInnerHTML={{ __html: icon }} />
      )}

      {/* Sticky bar — policy: anchor links / practice area: sibling page links */}
      {(hasAnchors || !isPolicy) && (
        <div
          className={`fixed left-0 w-full z-40 bg-white/95 backdrop-blur-md border-b border-stone-200 shadow-sm transition-all duration-300 ${barStuck ? 'translate-y-0 opacity-100' : '-translate-y-full opacity-0 pointer-events-none'}`}
          style={{ top: '4rem' }}
          aria-hidden={!barStuck}
        >
          <div className="max-w-7xl mx-auto px-6 py-3 rtl:text-right">
            {hasAnchors ? (
              <div
                className="text-stone-600 font-semibold tracking-wide text-sm"
                dangerouslySetInnerHTML={{ __html: scope }}
              />
            ) : (
              <nav className="flex flex-wrap gap-x-6 gap-y-1 text-sm" aria-label="Practice areas">
                {navAreas.map((area) => {
                  const isCurrent = area.key === areaKey;
                  return isCurrent ? (
                    <span
                      key={area.key}
                      className="text-gold font-bold"
                      aria-current="page"
                    >
                      {t(area.titleKey)}
                    </span>
                  ) : (
                    <Link
                      key={area.key}
                      href={area.path}
                      className="text-stone-500 hover:text-gold transition font-medium"
                    >
                      {t(area.titleKey)}
                    </Link>
                  );
                })}
              </nav>
            )}
          </div>
        </div>
      )}

      <div className="max-w-7xl mx-auto px-6">
        <div className="grid lg:grid-cols-3 gap-8 md:gap-12 items-start">
          {/* Left Content Area */}
          <div className="lg:col-span-2">
            <div className="mb-12 rtl:text-right">
              {!isPolicy && icon && (
                <div className="mb-6 text-gold" dangerouslySetInnerHTML={{ __html: icon }} />
              )}
              <h1 ref={titleRef} className="text-3xl sm:text-5xl md:text-7xl mb-6 leading-tight">{title}</h1>
              <p
                className="text-xl md:text-2xl text-stone-600 leading-relaxed max-w-2xl"
                dangerouslySetInnerHTML={{ __html: desc }}
              />
              {scope && (
                <div
                  ref={hasAnchors ? scopeRef : undefined}
                  className="mt-8 px-6 py-3 bg-stone-100 border-l-4 rtl:border-l-0 rtl:border-r-4 border-gold text-stone-600 font-semibold tracking-wide inline-block"
                  dangerouslySetInnerHTML={{ __html: scope }}
                />
              )}
            </div>

            {/* Content sections */}
            {hasSections && (
              <div className="space-y-16 mb-20">
                <div className="grid md:grid-cols-2 gap-6 md:gap-12">
                  {commonSituationsTitle && (
                    <div className="rtl:text-right">
                      <h2 className="text-3xl mb-6 text-stone-800 font-bold">{commonSituationsTitle}</h2>
                      <ul className="space-y-4 text-stone-600">
                        {Array.isArray(commonSituations) && commonSituations.map((item, i) => (
                          <li key={i} className="flex gap-3 items-start">
                            <span className="w-2 h-2 bg-gold rounded-full mt-2 flex-shrink-0" />
                            <span dangerouslySetInnerHTML={{ __html: item }} />
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {whatToDoTitle && (
                    <div className="rtl:text-right">
                      <h2 className="text-3xl mb-6 text-stone-800 font-bold">{whatToDoTitle}</h2>
                      <ul className="space-y-4 text-stone-600">
                        {Array.isArray(whatToDo) && whatToDo.map((item, i) => (
                          <li key={i} className="flex gap-3 items-start">
                            <span className="w-2 h-2 bg-gold rounded-full mt-2 flex-shrink-0" />
                            <span dangerouslySetInnerHTML={{ __html: item }} />
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
                {howIHelpTitle && (
                  <div className="rtl:text-right">
                    <h2 className="text-3xl mb-6 text-stone-800 font-bold">{howIHelpTitle}</h2>
                    <ul className="space-y-4 text-stone-600 max-w-2xl">
                      {Array.isArray(howIHelp) && howIHelp.map((item, i) => (
                        <li key={i} className="flex gap-3 items-start">
                          <span className="w-2 h-2 bg-gold rounded-full mt-2 flex-shrink-0" />
                          <span dangerouslySetInnerHTML={{ __html: item }} />
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {/* Services list */}
            {Array.isArray(services) && services.length > 0 && (
              <div className="mt-16 rtl:text-right">
                <div className="border-t-2 border-gold pt-8">
                  <h2 className="text-2xl font-bold mb-6 uppercase tracking-widest text-stone-600">
                    {servicesLabel}
                  </h2>
                  <ul className="grid md:grid-cols-2 gap-y-2 gap-x-4 text-stone-600">
                    {services.map((item, i) => (
                      <li key={i} className="flex gap-3 items-start">
                        <span className="w-2 h-2 bg-gold rounded-full mt-2 flex-shrink-0" />
                        <span dangerouslySetInnerHTML={{ __html: item }} />
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>

          {/* Right Sidebar CTA Card */}
          <div className="lg:col-span-1 lg:sticky lg:top-32">
            <div className="bg-stone-50 border border-stone-200 p-5 md:p-8 rounded-sm text-center shadow-sm">
              <h3 className="text-2xl mb-4 font-bold">{t('cta_title')}</h3>
              <p className="text-stone-600 mb-6 text-sm">{t('cta_desc')}</p>
              <Link
                href="/#contact"
                className="inline-block bg-gold text-white border-2 border-gold px-8 py-4 font-bold uppercase tracking-widest hover:bg-stone-900 hover:border-stone-900 transition w-full text-center"
              >
                {t('cta_button_sec')}
              </Link>
              <p className="mt-3 text-stone-600 text-xs">{t('cta_microcopy')}</p>

              <div className="mt-8 border-t border-stone-200 pt-6">
                <a
                  href="https://wa.me/972524203401"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center justify-center gap-2 bg-[#25D366] text-stone-900 border-2 border-[#25D366] px-8 py-3 hover:bg-[#1ebe5d] hover:border-[#1ebe5d] transition w-full text-center"
                >
                  <svg aria-hidden="true" className="flex-shrink-0" fill="currentColor" height="20" width="20" viewBox="0 0 16 16">
                    <path d="M13.601 2.326A7.854 7.854 0 0 0 7.994 0C3.627 0 .068 3.558.064 7.926c0 1.399.366 2.76 1.057 3.965L0 16l4.204-1.102a7.933 7.933 0 0 0 3.79.965h.004c4.368 0 7.926-3.558 7.93-7.93A7.898 7.898 0 0 0 13.6 2.326zM7.994 14.521a6.573 6.573 0 0 1-3.356-.92l-.24-.144-2.494.654.666-2.433-.156-.251a6.56 6.56 0 0 1-1.007-3.505c0-3.626 2.957-6.584 6.591-6.584a6.56 6.56 0 0 1 4.66 1.931 6.557 6.557 0 0 1 1.928 4.66c-.004 3.639-2.961 6.592-6.592 6.592zm3.615-4.934c-.197-.099-1.17-.578-1.353-.646-.182-.065-.315-.099-.445.099-.133.197-.513.646-.627.775-.114.133-.232.148-.43.05-.197-.1-.836-.308-1.592-.985-.59-.525-.985-1.175-1.103-1.372-.114-.198-.011-.304.088-.403.087-.088.197-.232.296-.346.1-.114.133-.198.198-.33.065-.134.034-.248-.015-.347-.05-.099-.445-1.076-.612-1.47-.16-.389-.323-.335-.445-.34-.114-.007-.247-.007-.38-.007a.729.729 0 0 0-.529.247c-.182.198-.691.677-.691 1.654 0 .977.71 1.916.81 2.049.098.133 1.394 2.132 3.383 2.992.47.205.84.326 1.129.418.475.152.904.129 1.246.08.38-.058 1.171-.48 1.338-.943.164-.464.164-.86.114-.943-.049-.084-.182-.133-.38-.232z" />
                  </svg>
                  <span className="text-sm font-semibold">{t('whatsapp_btn')}</span>
                </a>
              </div>
            </div>

            {/* What happens next - hidden for policy pages */}
            {!isPolicy && (
              <div className="mt-8 p-5 md:p-8 bg-stone-900 text-white rounded-sm rtl:text-right">
                <h4 className="text-xl font-bold mb-6 border-b border-stone-700 pb-4">
                  {t('next_steps_title')}
                </h4>
                <ol className="space-y-6">
                  {[1, 2, 3].map((n) => (
                    <li key={n} className="flex gap-4 items-start">
                      <span className="bg-gold text-white w-6 h-6 rounded-full flex items-center justify-center font-bold text-xs flex-shrink-0">
                        {n}
                      </span>
                      <div>
                        <p className="font-bold text-sm">{t(`step${n}_title`)}</p>
                        <p className="text-stone-400 text-xs mt-1">{t(`step${n}_desc`)}</p>
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        </div>
      </div>
    </main>
  );
}
