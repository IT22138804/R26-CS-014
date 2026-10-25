export default function MetricCard({
  title,
  value,
  unit,
  icon: Icon,
  subtitle
}) {
  return (
    <article className="metric-card">
      <div className="metric-card__icon">{Icon ? <Icon size={22} /> : null}</div>
      <div>
        <p className="metric-card__title">{title}</p>
        <p className="metric-card__value">
          {value}
          {unit ? <span>{unit}</span> : null}
        </p>
        {subtitle ? <p className="metric-card__subtitle">{subtitle}</p> : null}
      </div>
    </article>
  );
}
