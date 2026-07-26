import { Label, Select } from './ui';

export function ContextSelect({
  label,
  value,
  onChange,
  options,
  placeholder,
  disabled,
  testId,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  placeholder: string;
  disabled?: boolean;
  testId: string;
}) {
  return (
    <div className="min-w-[160px] flex-1">
      <Label className="sr-only">{label}</Label>
      <Select
        data-testid={testId}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        aria-label={label}
      >
        <option value="">{placeholder}</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}
