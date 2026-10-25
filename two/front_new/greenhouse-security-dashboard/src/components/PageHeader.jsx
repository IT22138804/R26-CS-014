export default function PageHeader({ eyebrow, title, description, action }) {
  return (
    <div className="page-header">
      <div>
        <span className="page-header__eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}
