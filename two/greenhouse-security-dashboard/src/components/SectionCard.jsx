export default function SectionCard({ title, subtitle, action, children, className = "" }) {
  return (
    <section className={`section-card ${className}`}>
      <header className="section-card__header">
        <div>
          <h2>{title}</h2>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
        {action}
      </header>
      <div className="section-card__body">{children}</div>
    </section>
  );
}
