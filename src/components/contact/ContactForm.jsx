'use client';
import { useState, useRef } from 'react';
import { useTranslation } from 'react-i18next';

export default function ContactForm() {
  const { t, i18n } = useTranslation();
  const [success, setSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errors, setErrors] = useState({});
  const [apiError, setApiError] = useState('');
  const [selectOpen, setSelectOpen] = useState(false);
  const selectRef = useRef(null);

  const clearError = (field) => {
    setErrors((prev) => ({ ...prev, [field]: '' }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const form = e.target;
    const name = form['full-name'].value.trim();
    const phone = form.phone.value.trim();
    const caseType = form['case-type'].value;
    const email = form['email-address'].value.trim();
    const message = form['message-summary'].value.trim();

    // Get the display text of the selected option
    const sel = form['case-type'];
    const caseTypeLabel = sel.options[sel.selectedIndex]?.text || caseType;

    const newErrors = {};
    if (!name) newErrors['full-name'] = t('err_name') || 'Required';
    if (!phone) {
      newErrors.phone = t('err_phone') || 'Required';
    } else if (!/^[\d\s\-+().]+$/.test(phone)) {
      newErrors.phone = t('err_phone_format') || 'Invalid phone number format';
    }
    if (!caseType) newErrors['case-type'] = t('err_case_type') || 'Required';
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      newErrors['email-address'] = t('err_email') || 'Invalid email';
    }
    if (!message || message.length < 10) {
      newErrors['message-summary'] = t('err_message') || 'At least 10 characters';
    }

    setErrors(newErrors);
    if (Object.keys(newErrors).length > 0) return;

    setSubmitting(true);
    setApiError('');

    try {
      const res = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          phone,
          caseType: caseTypeLabel,
          email: email || undefined,
          message,
          lang: i18n.language,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setApiError(data.error || t('err_generic') || 'Something went wrong. Please try again.');
      } else {
        setSuccess(true);
      }
    } catch {
      setApiError(t('err_generic') || 'Something went wrong. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleReset = () => {
    setSuccess(false);
    setErrors({});
    setApiError('');
  };

  if (success) {
    return (
      <div className="py-10 text-center" role="status" aria-live="assertive">
        <svg aria-hidden="true" className="w-20 h-20 mx-auto mb-6" viewBox="0 0 52 52">
          <circle
            className="success-circle"
            cx="26" cy="26" r="24"
            fill="none"
            stroke="#16a34a"
            strokeWidth="2"
          />
          <path
            className="success-check"
            fill="none"
            stroke="#16a34a"
            strokeWidth="3"
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M15 27l7 7 15-15"
          />
        </svg>
        <h3 className="text-2xl mb-3 success-fade">{t('form_success_title')}</h3>
        <p className="text-stone-400 mb-6 success-fade">{t('form_success_desc')}</p>
        <button onClick={handleReset} className="text-gold underline text-sm cursor-pointer success-fade">
          {t('form_success_back')}
        </button>
      </div>
    );
  }

  return (
    <form className="grid md:grid-cols-2 gap-6 text-left rtl:text-right" onSubmit={handleSubmit} noValidate>
      <div>
        <label htmlFor="full-name" className="block text-xs uppercase tracking-widest text-stone-400 mb-2">
          {t('form_name')}
        </label>
        <input
          type="text"
          id="full-name"
          name="full-name"
          required
          aria-required="true"
          aria-describedby="full-name-error"
          onChange={() => clearError('full-name')}
          className={`w-full bg-stone-800 border-stone-700 border p-4 focus:border-gold outline-none transition placeholder:font-light ${errors['full-name'] ? 'input-error' : ''}`}
          placeholder={t('form_name_placeholder')}
        />
        {errors['full-name'] && (
          <span id="full-name-error" className="text-red-400 text-xs mt-1 block" role="alert">
            {errors['full-name']}
          </span>
        )}
      </div>
      <div>
        <label htmlFor="phone" className="block text-xs uppercase tracking-widest text-stone-400 mb-2">
          {t('form_phone')}
        </label>
        <input
          type="tel"
          id="phone"
          name="phone"
          required
          aria-required="true"
          aria-describedby="phone-error"
          onChange={() => clearError('phone')}
          className={`w-full bg-stone-800 border-stone-700 border p-4 focus:border-gold outline-none transition placeholder:font-light text-left rtl:text-right ${errors.phone ? 'input-error' : ''}`}
          placeholder={t('form_phone_placeholder')}
        />
        {errors.phone && (
          <span id="phone-error" className="text-red-400 text-xs mt-1 block" role="alert">
            {errors.phone}
          </span>
        )}
      </div>
      <div className="relative">
        <label htmlFor="case-type" className="block text-xs uppercase tracking-widest text-stone-400 mb-2">
          {t('form_case_type')}
        </label>
        <div className={`relative ${selectOpen ? 'select-open' : ''}`}>
          <select
            ref={selectRef}
            id="case-type"
            name="case-type"
            required
            aria-required="true"
            aria-describedby="case-type-error"
            defaultValue=""
            onChange={() => clearError('case-type')}
            onFocus={() => setSelectOpen(true)}
            onBlur={() => setSelectOpen(false)}
            className={`w-full bg-stone-800 border-stone-700 border p-4 focus:border-gold outline-none transition appearance-none cursor-pointer ${errors['case-type'] ? 'input-error' : ''}`}
          >
            <option value="" disabled>{t('opt_select')}</option>
            <option value="criminal">{t('opt_criminal')}</option>
            <option value="transport">{t('opt_transport')}</option>
            <option value="admin">{t('opt_admin')}</option>
            <option value="labour">{t('opt_labour')}</option>
            <option value="accessibility">{t('opt_accessibility')}</option>
            <option value="other">{t('opt_other')}</option>
          </select>
          <div className="absolute inset-y-0 right-0 rtl:right-auto rtl:left-0 flex items-center px-4 pointer-events-none transition-transform duration-300 select-arrow">
            <svg aria-hidden="true" className="w-4 h-4 text-stone-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </div>
        </div>
        {errors['case-type'] && (
          <span id="case-type-error" className="text-red-400 text-xs mt-1 block" role="alert">
            {errors['case-type']}
          </span>
        )}
      </div>
      <div>
        <label htmlFor="email-address" className="block text-xs uppercase tracking-widest text-stone-400 mb-2">
          {t('form_email')}
        </label>
        <input
          type="email"
          id="email-address"
          name="email-address"
          aria-describedby="email-error"
          onChange={() => clearError('email-address')}
          className={`w-full bg-stone-800 border-stone-700 border p-4 focus:border-gold outline-none transition placeholder:font-light ${errors['email-address'] ? 'input-error' : ''}`}
          placeholder={t('form_email_placeholder')}
        />
        {errors['email-address'] && (
          <span id="email-error" className="text-red-400 text-xs mt-1 block" role="alert">
            {errors['email-address']}
          </span>
        )}
      </div>
      <div className="md:col-span-2">
        <label htmlFor="message-summary" className="block text-xs uppercase tracking-widest text-stone-400 mb-2">
          {t('form_message')}
        </label>
        <textarea
          id="message-summary"
          name="message-summary"
          rows={4}
          minLength={10}
          required
          aria-required="true"
          aria-describedby="message-error"
          onChange={() => clearError('message-summary')}
          className={`w-full bg-stone-800 border-stone-700 border p-4 focus:border-gold outline-none transition placeholder:font-light ${errors['message-summary'] ? 'input-error' : ''}`}
          placeholder={t('form_message_placeholder')}
        />
        {errors['message-summary'] && (
          <span id="message-error" className="text-red-400 text-xs mt-1 block" role="alert">
            {errors['message-summary']}
          </span>
        )}
      </div>
      {apiError && (
        <div className="md:col-span-2 text-red-400 text-sm text-center" role="alert">
          {apiError}
        </div>
      )}
      <button
        type="submit"
        disabled={submitting}
        className="md:col-span-2 bg-gold text-white font-bold uppercase tracking-widest py-5 hover:bg-white hover:text-stone-900 transition disabled:opacity-50 cursor-pointer"
      >
        {submitting ? '...' : t('form_submit')}
      </button>
    </form>
  );
}
