"""Defence-time demo: run the full HSA analysis on a small, fast contract set and render a
self-contained HTML report with charts.

This is a presentation wrapper, not part of the method. It calls `hsa.cli.analyze` (the same entry
point the dataset runs use), so what the commission sees on screen is exactly what chapter 3 reports
-- no second implementation of anything. The output is a single offline HTML file (inline CSS and
inline SVG charts, no server, no CDN), so it opens in any browser with no network.

Run it:

    python -m experiments.demo            # analyse the default set, write + open the HTML
    python -m experiments.demo --quick    # only the 0.8.x contracts (skips the two 0.4.x OV ones)
    python -m experiments.demo --no-open  # do not launch the browser (CI / headless)

The contracts are the thesis fixtures in `tests/contracts/`: small, deterministic, and each with a
known verdict, so the live demo always shows the same story -- vulnerable contracts CONFIRMED with a
concrete counterexample, their fixed twins REFUTED or without any target at all.
"""

from __future__ import annotations

import argparse
import html
import time
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from hsa.cli import analyze
from hsa.config import Config, Mode
from hsa.model import Verdict

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "tests" / "contracts"
OUT = ROOT / "experiments" / "runs" / "demo.html"

#: Colour per verdict, reused by the cards, the table and the charts.
VERDICT_COLOR = {
    "CONFIRMED": "#e5484d",  # red: a real, witnessed vulnerability
    "REFUTED": "#30a46c",  # green: the symbolic stage cleared the static warning
    "UNKNOWN": "#f5a623",  # amber: no decision within the budget
}
VERDICT_LABEL = {
    "CONFIRMED": "Підтверджено",
    "REFUTED": "Спростовано",
    "UNKNOWN": "Не визначено",
}
CLASS_COLOR = {
    "SC08": "#e5484d",
    "SC06": "#f5a623",
    "SC01": "#4c6ef5",
    "SC09": "#9c36b5",
    "SC10": "#0ca678",
}

#: Plain-language description of every class the method handles: what it is and what an attacker can
#: actually do with it. Shown in the class guide and under each CONFIRMED target.
CLASS_INFO = {
    "SC01": (
        "Контроль доступу",
        "Привілейовану дію (зміна власника, selfdestruct, адреса реалізації) може виконати будь-хто, "
        "бо вона не захищена перевіркою msg.sender — або захищена через tx.origin, який підробляється.",
        "Зловмисник стає власником контракту чи знищує його та виводить усі кошти.",
    ),
    "SC06": (
        "Неперевірений виклик",
        "Результат низькорівневого виклику (call / send) не перевіряється, і виконання триває так, "
        "ніби переказ відбувся успішно.",
        "Кошти вважаються надісланими, хоча переказ міг не пройти — втрата коштів або неузгоджений стан.",
    ),
    "SC08": (
        "Повторний вхід (reentrancy)",
        "Зовнішній виклик передає керування зловмиснику ДО того, як оновиться стан (баланс), і той "
        "рекурсивно викликає ту саму функцію знову, доки стан ще старий.",
        "Виведення набагато більше коштів, ніж належить, — класична атака на The DAO (2016).",
    ),
    "SC09": (
        "Переповнення цілого",
        "Арифметичне переповнення або від'ємне переповнення (до Solidity 0.8 операції не мають "
        "вбудованих перевірок меж).",
        "Баланс «обертається» на величезне число — безпідставне збагачення чи обхід перевірок меж.",
    ),
    "SC10": (
        "Delegatecall",
        "Делегований виклик за адресою, яку задає зловмисник: чужий код виконується у контексті "
        "(сховищі) цього контракту.",
        "Повне захоплення контракту — зловмисник переписує будь-яку змінну, зокрема власника.",
    ),
}

#: Per-target plain-language explanation for the commission: what exactly is wrong (the mechanism,
#: step by step, no Solidity knowledge assumed) and the remediation. Keyed by the VulnClass name, so
#: AC and TO -- two predicates over SC01 -- get different texts.
EXPLAIN = {
    "RE": (
        "Контракт спершу надсилає кошти зовнішній адресі, а баланс обнуляє ЛИШЕ ПОТІМ. Отримувачем "
        "може бути контракт зловмисника: отримавши переказ, він одразу викликає цю саму функцію "
        "знову. Баланс ще не обнулено, тож перевірка проходить повторно і кошти виводяться ще раз — "
        "і так по колу, доки контракт не спорожніє. Проблема саме в ПОСЛІДОВНОСТІ: виклик стоїть "
        "перед оновленням стану.",
        "Оновлювати стан ДО зовнішнього виклику (шаблон «перевірки → зміни → взаємодія», CEI): "
        "спершу обнулити баланс, і лише потім надсилати кошти. Або поставити замок — модифікатор "
        "nonReentrant, що блокує повторний вхід у функцію.",
    ),
    "UC": (
        "Низькорівневий виклик (call / send) повертає прапорець успіху, але контракт його не "
        "перевіряє і працює далі так, ніби переказ пройшов. Якщо виклик насправді не вдався (у "
        "отримувача бракує газу чи він відхилив переказ), стан оновлюється неправильно — кошти "
        "вважаються надісланими, хоча їх немає.",
        "Перевіряти результат виклику: require(ok) або if (!ok) revert(). Альтернатива — transfer, "
        "який сам відкочує транзакцію при невдачі.",
    ),
    "AC": (
        "Привілейовану дію (зміну власника, знищення контракту) може виконати будь-хто: перед нею "
        "немає перевірки, що викликач — власник. Тобто сторонній користувач однією транзакцією "
        "робить себе власником або знищує контракт.",
        "Додати перевірку доступу на початку функції: модифікатор onlyOwner або "
        "require(msg.sender == owner).",
    ),
    "TO": (
        "Права перевіряються через tx.origin замість msg.sender. tx.origin — це перший ініціатор "
        "усього ланцюжка викликів. Якщо власника обманом змусити звернутися до контракту "
        "зловмисника, той усередині викличе цю функцію, і tx.origin усе одно дорівнюватиме "
        "власнику — перевірка пройде за зловмисника (фішинг-атака).",
        "Для перевірки прав використовувати msg.sender (безпосереднього викликача), а не tx.origin.",
    ),
    "DC": (
        "delegatecall виконує код за вказаною адресою, але у СХОВИЩІ поточного контракту. Якщо "
        "адресу задає зловмисник, він підставляє власний контракт, код якого переписує будь-яку "
        "змінну цього контракту — зокрема власника — і повністю захоплює його.",
        "Не дозволяти задавати адресу delegatecall ззовні: фіксувати адресу реалізації або "
        "захищати її зміну контролем доступу.",
    ),
    "OV": (
        "До Solidity 0.8 арифметика не перевіряє меж. Якщо відняти від балансу більше, ніж на ньому "
        "є, результат не стає від'ємним, а «обертається» на величезне число (близько 2^256). "
        "Користувач із нульовим балансом отримує астрономічну суму.",
        "Перейти на Solidity ≥ 0.8 (перевірки меж вбудовано) або використати бібліотеку SafeMath / "
        "явні require меж перед операцією.",
    ),
}

#: Meaning of each verdict, spelled out for the commission (shown as a legend panel).
VERDICT_HELP = {
    "CONFIRMED": "Знайдено конкретний вхід (контрприклад), що реалізує вразливість. Реальна загроза.",
    "REFUTED": "Статичний етап позначив місце як підозріле, але символьне виконання довело, що "
    "ЖОДЕН вхід не може реалізувати атаку (захищено, напр., nonReentrant або require). "
    "У цьому місці вразливості немає.",
    "UNKNOWN": "За відведений бюджет вирішити не вдалося: таймаут або непідтримувана конструкція.",
}

#: What each column of the target table means.
COLUMN_HELP = [
    ("Клас", "Клас вразливості за класифікацією SWC та його підтип."),
    ("Функція:рядок", "Де саме в коді розташована ціль — функція і номер рядка."),
    (
        "Вердикт / контрприклад",
        "Результат символьного етапу. Для «Підтверджено» наведено контрприклад — конкретний вхід "
        "(функція, sender, аргументи), яким відтворюється атака.",
    ),
    ("R", "Ризик R(t) ∈ [0;1] (формула 2.16): критичність класу × контрольованість × незахищеність × "
     "наявність цінностей. Наскільки серйозна ціль."),
    ("P", "Пріоритет P(t) ∈ [0;1] (формула 2.17): ризик R, зважений на складність перевірки "
     "(кількість розгалужень). Визначає порядок цілі в черзі аналізу."),
]


@dataclass
class DemoCase:
    """One contract in the demo, with the one-line story the presenter tells about it."""

    filename: str
    group: str  # the vulnerability class heading it sits under
    story: str  # what the commission should take away from this contract
    #: solc version, pinned exactly as the tests pin it (tests/conftest.py PINNED). Pinned rather
    #: than auto-detected because `prep.select_version` also reads `pragma` lines that appear inside
    #: comments, and several fixtures mention an older pragma in a comment (e.g. Reentrancy_if).
    version: tuple[int, int, int] = (0, 8, 20)
    quick: bool = True  # False for the slow 0.4.x contracts, skipped by --quick

    @property
    def path(self) -> Path:
        return CONTRACTS / self.filename


#: The demo set, grouped as a "vulnerable vs fixed" narrative. Order is the order shown.
DEMO_SET: list[DemoCase] = [
    DemoCase(
        "Vault.sol",
        "Повторний вхід (SC08)",
        "Класичний reentrancy: запис балансу після зовнішнього виклику. Очікується CONFIRMED із контрприкладом.",
    ),
    DemoCase(
        "Vault_fixed_guard.sol",
        "Повторний вхід (SC08)",
        "Той самий контракт із модифікатором nonReentrant. Статичний етап усе ще бачить ціль, символьний — спростовує її (REFUTED).",
    ),
    DemoCase(
        "Vault_fixed_cei.sol",
        "Повторний вхід (SC08)",
        "Виправлення за шаблоном CEI (запис до виклику). Жодної цілі: вразливість відсіює вже статичний етап.",
    ),
    DemoCase(
        "Reentrancy_if.sol",
        "Повторний вхід (SC08)",
        "Reentrancy у стилі SimpleDAO з розгалуженням. Одночасно підтверджує RE і неперевірений виклик (SC06).",
    ),
    DemoCase(
        "Access_unprotected.sol",
        "Контроль доступу (SC01)",
        "Незахищена зміна власника (CONFIRMED) поруч із захищеним selfdestruct (REFUTED за моделлю атакувальника).",
    ),
    DemoCase(
        "Tx_origin.sol",
        "Контроль доступу (SC01)",
        "Автентифікація через tx.origin замість msg.sender — окрема ціль TO.",
    ),
    DemoCase(
        "Unchecked_call.sol",
        "Неперевірений виклик (SC06)",
        "Результат low-level call не перевірено, далі йде запис у сховище. Позитив і негатив в одному контракті.",
    ),
    DemoCase(
        "Delegatecall_proxy.sol",
        "Delegatecall (SC10)",
        "Контрольований delegatecall у проксі: адреса реалізації задається ззовні.",
    ),
    DemoCase(
        "Overflow_sub.sol",
        "Переповнення (SC09)",
        "Відрахування без перевірки меж на solc 0.4.24 → CONFIRMED (∀ баланс < 2^255 ∃ amount).",
        version=(0, 4, 24),
        quick=False,
    ),
    DemoCase(
        "Overflow_guarded.sol",
        "Переповнення (SC09)",
        "Те саме відрахування, але під require меж → REFUTED. Пара до попереднього.",
        version=(0, 4, 24),
        quick=False,
    ),
]


@dataclass
class CaseResult:
    """A demo case joined with its analysis report, flattened for rendering."""

    case: DemoCase
    solc: Optional[str]
    elapsed: float
    error: Optional[str]
    targets: list[dict] = field(default_factory=list)
    verdict_counts: dict[str, int] = field(default_factory=dict)


def run_case(case: DemoCase) -> CaseResult:
    """Analyse one contract under the full method (M1) and flatten the report for the HTML."""
    report = analyze(case.path, Config(mode=Mode.M1), version=case.version)
    targets = [result.to_json() for result in report.results]
    counts = {verdict.value: 0 for verdict in Verdict}
    for target in targets:
        counts[target["verdict"]] += 1
    solc = ".".join(str(part) for part in report.solc_version) if report.solc_version else None
    return CaseResult(
        case=case,
        solc=solc,
        elapsed=report.elapsed,
        error=report.error,
        targets=targets,
        verdict_counts=counts,
    )


# --------------------------------------------------------------------------------------------------
# SVG charts. Pure Python so the HTML stays self-contained (no JS charting library, no CDN).
# --------------------------------------------------------------------------------------------------


def donut(counts: dict[str, int], size: int = 180) -> str:
    """A donut chart of the verdict distribution. Empty -> a grey ring."""
    total = sum(counts.values())
    radius, stroke = size / 2 - 16, 26
    cx = cy = size / 2
    circumference = 2 * 3.141592653589793 * radius
    if total == 0:
        return (
            f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">'
            f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="#2a2a33" '
            f'stroke-width="{stroke}"/></svg>'
        )
    segments, offset = [], 0.0
    for name in ("CONFIRMED", "UNKNOWN", "REFUTED"):
        value = counts.get(name, 0)
        if not value:
            continue
        length = circumference * value / total
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" '
            f'stroke="{VERDICT_COLOR[name]}" stroke-width="{stroke}" '
            f'stroke-dasharray="{length:.2f} {circumference - length:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>'
        )
        offset += length
    middle = (
        f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" fill="#eceef2" '
        f'font-size="34" font-weight="700">{total}</text>'
        f'<text x="{cx}" y="{cy + 20}" text-anchor="middle" fill="#9aa0ad" '
        f'font-size="13">цілей</text>'
    )
    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">'
        + "".join(segments)
        + middle
        + "</svg>"
    )


def bar_chart(
    data: list[tuple[str, int, str]], width: int = 460, bar_h: int = 26, label_w: int = 140
) -> str:
    """A horizontal bar chart: list of (label, value, colour). Scaled to the largest value.

    Labels sit in their own left column of `label_w` px and are right-aligned up against the bars,
    so Ukrainian words are never clipped by the plot (what the first screenshot showed).
    """
    if not data:
        return '<p class="muted">немає даних</p>'
    top = max(value for _, value, _ in data) or 1
    gap, value_pad = 14, 40
    plot_w = width - label_w - value_pad
    height = len(data) * (bar_h + gap)
    rows = []
    for index, (label, value, color) in enumerate(data):
        y = index * (bar_h + gap)
        length = max(plot_w * value / top, 2)
        rows.append(
            f'<text x="{label_w - 10}" y="{y + bar_h / 2 + 5}" text-anchor="end" fill="#c3c7d1" '
            f'font-size="14" font-weight="600">{html.escape(label)}</text>'
            f'<rect x="{label_w}" y="{y}" width="{length:.1f}" height="{bar_h}" '
            f'rx="5" fill="{color}"/>'
            f'<text x="{label_w + length + 8:.1f}" y="{y + bar_h / 2 + 5}" '
            f'fill="#eceef2" font-size="14" font-weight="700">{value}</text>'
        )
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'preserveAspectRatio="xMinYMid meet">' + "".join(rows) + "</svg>"
    )


def funnel(contracts: int, targets: int, counts: dict[str, int]) -> str:
    """The two-stage pipeline as a small funnel: contracts -> static targets -> verdicts."""
    stages = [
        ("Контракти", contracts, "#4c6ef5"),
        ("Статичні цілі", targets, "#8a63d2"),
        ("Підтверджено", counts.get("CONFIRMED", 0), VERDICT_COLOR["CONFIRMED"]),
        ("Спростовано", counts.get("REFUTED", 0), VERDICT_COLOR["REFUTED"]),
    ]
    return bar_chart(list(stages))


# --------------------------------------------------------------------------------------------------
# HTML assembly.
# --------------------------------------------------------------------------------------------------


def _counterexample_html(cex: Optional[dict]) -> str:
    if not cex:
        return ""
    rows = [f"<b>функція:</b> {html.escape(str(cex.get('function', '')))}"]
    if cex.get("sender"):
        rows.append(f"<b>sender:</b> {html.escape(str(cex['sender']))}")
    if cex.get("value"):
        rows.append(f"<b>value:</b> {html.escape(str(cex['value']))}")
    for name, val in (cex.get("arguments") or {}).items():
        rows.append(f"<b>{html.escape(name)}:</b> {html.escape(str(val))}")
    if cex.get("reentry_function"):
        rows.append(f"<b>повторний виклик:</b> {html.escape(str(cex['reentry_function']))}")
    return '<div class="cex">' + " · ".join(rows) + "</div>"


def _targets_table(result: CaseResult) -> str:
    if result.error:
        return f'<p class="err">Помилка компіляції: {html.escape(result.error)}</p>'
    if not result.targets:
        return (
            '<p class="safe">Жодної цілі.</p>'
            '<p class="note">Це НЕ означає порожній контракт: статичний етап не знайшов жодної '
            "підозрілої точки, бо шаблон, який у вразливій версії давав ціль, тут усунуто "
            "(наприклад, запис стану ДО зовнішнього виклику за шаблоном CEI). Відповідний клас "
            "вразливості знято ще до символьного етапу.</p>"
        )
    rows = []
    for target in result.targets:
        verdict = target["verdict"]
        reason = f' <span class="reason">({html.escape(target["reason"])})</span>' if target["reason"] else ""
        func = html.escape(target["function"].split(".")[-1])
        line = target["line"] if target["line"] is not None else "-"
        cex = _counterexample_html(target.get("counterexample"))
        detail = ""
        if verdict == "CONFIRMED":
            danger = CLASS_INFO.get(target["swc"], ("", "", ""))[2]
            why, fix = EXPLAIN.get(target["class"], ("", ""))
            explain = (
                '<div class="explain">'
                f'<div class="ex-why"><b>Що тут вразливе і чому.</b> {html.escape(why)}</div>'
                f'<div class="ex-fix"><b>Як виправити.</b> {html.escape(fix)}</div>'
                "</div>"
                if why
                else ""
            )
            detail = (
                cex
                + f'<div class="danger">Чим небезпечно: {html.escape(danger)}</div>'
                + explain
            )
        elif verdict == "REFUTED":
            detail = (
                '<div class="refnote">Символьний етап довів, що жоден вхід не реалізує цю '
                "ціль — у цьому місці вразливості немає.</div>"
            )
        rows.append(
            "<tr>"
            f'<td><span class="chip" style="background:{CLASS_COLOR.get(target["swc"], "#555")}">'
            f'{html.escape(target["swc"])}</span> {html.escape(target["class"])}</td>'
            f"<td>{func}:{line}</td>"
            f'<td><span class="verdict" style="color:{VERDICT_COLOR[verdict]}">'
            f"{VERDICT_LABEL[verdict]}</span>{reason}{detail}</td>"
            f'<td class="num">{target["R"]:.3f}</td>'
            f'<td class="num">{target["P"]:.3f}</td>'
            "</tr>"
        )
    return (
        '<table class="targets"><thead><tr>'
        "<th>Клас</th><th>Функція:рядок</th><th>Вердикт / контрприклад</th>"
        "<th>R</th><th>P</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _source_html(result: CaseResult) -> str:
    """Collapsible, line-numbered source of the contract, with target lines highlighted."""
    try:
        text = result.case.path.read_text(encoding="utf-8")
    except OSError:
        return ""
    target_lines = {
        target["line"]: target["verdict"]
        for target in result.targets
        if target["line"] is not None
    }
    lines = []
    for number, content in enumerate(text.splitlines(), 1):
        mark = target_lines.get(number)
        style = f' style="border-left:3px solid {VERDICT_COLOR[mark]}"' if mark else ""
        klass = ' class="hit"' if mark else ""
        lines.append(
            f'<div class="srcline"{klass}{style}>'
            f'<span class="ln">{number}</span>'
            f'<span class="code">{html.escape(content) or "&nbsp;"}</span></div>'
        )
    return (
        '<details class="source"><summary>Переглянути код контракту</summary>'
        f'<div class="srcbody">{"".join(lines)}</div></details>'
    )


def _case_card(result: CaseResult) -> str:
    counts = result.verdict_counts
    pills = "".join(
        f'<span class="pill" style="background:{VERDICT_COLOR[name]}22;color:{VERDICT_COLOR[name]}">'
        f"{VERDICT_LABEL[name]}: {counts[name]}</span>"
        for name in ("CONFIRMED", "REFUTED", "UNKNOWN")
        if counts.get(name)
    )
    return (
        '<div class="case">'
        f'<div class="case-head"><h3>{html.escape(result.case.filename)}</h3>'
        f'<span class="meta">solc {html.escape(result.solc or "-")} · {result.elapsed:.2f}s</span></div>'
        f'<p class="story">{html.escape(result.case.story)}</p>'
        f'<div class="pills">{pills}</div>'
        f"{_targets_table(result)}"
        f"{_source_html(result)}"
        "</div>"
    )


def _group_sections(results: list[CaseResult]) -> str:
    sections, seen = [], []
    for result in results:
        group = result.case.group
        if group not in seen:
            seen.append(group)
    for group in seen:
        cards = "".join(_case_card(r) for r in results if r.case.group == group)
        sections.append(f'<section><h2>{html.escape(group)}</h2>{cards}</section>')
    return "".join(sections)


def _class_guide(present: set[str]) -> str:
    """Explain every vulnerability class that appears in the run: what it is and the danger."""
    cards = []
    for swc in ("SC01", "SC06", "SC08", "SC09", "SC10"):
        if swc not in present:
            continue
        name, what, danger = CLASS_INFO[swc]
        cards.append(
            '<div class="guide-card">'
            f'<div class="guide-head"><span class="chip" style="background:{CLASS_COLOR[swc]}">'
            f"{swc}</span> {html.escape(name)}</div>"
            f'<p class="guide-what">{html.escape(what)}</p>'
            f'<p class="guide-danger"><b>Загроза:</b> {html.escape(danger)}</p>'
            "</div>"
        )
    return (
        '<section><h2>Класи вразливостей</h2>'
        f'<div class="guide-grid">{"".join(cards)}</div></section>'
    )


def _read_guide() -> str:
    """Explain the three verdicts and every column of the result tables."""
    verdicts = "".join(
        f'<div class="vrow"><span class="vdot" style="background:{VERDICT_COLOR[name]}"></span>'
        f'<div><b style="color:{VERDICT_COLOR[name]}">{VERDICT_LABEL[name]}</b> — '
        f"{html.escape(VERDICT_HELP[name])}</div></div>"
        for name in ("CONFIRMED", "REFUTED", "UNKNOWN")
    )
    columns = "".join(
        f"<li><b>{html.escape(label)}</b> — {html.escape(text)}</li>"
        for label, text in COLUMN_HELP
    )
    return (
        '<section><h2>Як читати результати</h2>'
        '<div class="panels2">'
        f'<div class="panel"><h3>Вердикти</h3>{verdicts}</div>'
        f'<div class="panel"><h3>Колонки таблиці</h3><ul class="cols">{columns}</ul></div>'
        "</div></section>"
    )


def build_html(results: list[CaseResult], elapsed: float) -> str:
    total_targets = sum(sum(r.verdict_counts.values()) for r in results)
    totals = {name: 0 for name in VERDICT_COLOR}
    class_counts: dict[str, int] = {}
    for result in results:
        for name, value in result.verdict_counts.items():
            totals[name] += value
        for target in result.targets:
            class_counts[target["swc"]] = class_counts.get(target["swc"], 0) + 1

    cards_top = "".join(
        f'<div class="stat"><div class="stat-num">{value}</div>'
        f'<div class="stat-lbl">{label}</div></div>'
        for label, value in (
            ("Контрактів", len(results)),
            ("Статичних цілей", total_targets),
            ("Підтверджено", totals["CONFIRMED"]),
            ("Спростовано", totals["REFUTED"]),
            ("Не визначено", totals["UNKNOWN"]),
        )
    )
    class_bars = bar_chart(
        [
            (swc, class_counts[swc], CLASS_COLOR.get(swc, "#555"))
            for swc in sorted(class_counts, key=lambda s: class_counts[s], reverse=True)
        ]
    )
    legend = "".join(
        f'<span class="leg"><i style="background:{VERDICT_COLOR[name]}"></i>{VERDICT_LABEL[name]}</span>'
        for name in ("CONFIRMED", "REFUTED", "UNKNOWN")
    )
    class_guide = _class_guide(set(class_counts))
    read_guide = _read_guide()
    return f"""<!doctype html>
<html lang="uk"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HSA — демонстрація аналізу</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#15161c; color:#eceef2;
    font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; line-height:1.5; }}
  header {{ padding:32px 40px 20px; border-bottom:1px solid #2a2a33;
    background:linear-gradient(180deg,#1b1d26,#15161c); }}
  header h1 {{ margin:0 0 4px; font-size:26px; }}
  header p {{ margin:0; color:#9aa0ad; }}
  main {{ max-width:1080px; margin:0 auto; padding:28px 40px 64px; }}
  .stats {{ display:flex; gap:14px; flex-wrap:wrap; margin:0 0 28px; }}
  .stat {{ flex:1; min-width:140px; background:#1f2029; border:1px solid #2a2a33;
    border-radius:12px; padding:16px 18px; }}
  .stat-num {{ font-size:32px; font-weight:800; }}
  .stat-lbl {{ color:#9aa0ad; font-size:13px; margin-top:2px; }}
  .panels {{ display:grid; grid-template-columns:1fr 1.3fr; gap:18px; margin-bottom:34px; }}
  .panel {{ background:#1f2029; border:1px solid #2a2a33; border-radius:12px; padding:20px; }}
  .panel h3 {{ margin:0 0 14px; font-size:15px; color:#c3c7d1; font-weight:600; }}
  .donut-wrap {{ display:flex; align-items:center; gap:18px; }}
  .legend {{ display:flex; flex-direction:column; gap:8px; }}
  .leg {{ display:flex; align-items:center; gap:8px; font-size:14px; color:#c3c7d1; }}
  .leg i {{ width:12px; height:12px; border-radius:3px; display:inline-block; }}
  section {{ margin:34px 0 0; }}
  section h2 {{ font-size:18px; border-left:3px solid #4c6ef5; padding-left:10px; margin:0 0 14px; }}
  .case {{ background:#1f2029; border:1px solid #2a2a33; border-radius:12px;
    padding:18px 20px; margin-bottom:14px; }}
  .case-head {{ display:flex; justify-content:space-between; align-items:baseline; gap:12px; }}
  .case-head h3 {{ margin:0; font-size:16px; font-family:ui-monospace,Menlo,Consolas,monospace; }}
  .meta {{ color:#9aa0ad; font-size:13px; white-space:nowrap; }}
  .story {{ color:#b6bac4; margin:6px 0 12px; font-size:14px; }}
  .pills {{ margin-bottom:10px; display:flex; gap:8px; flex-wrap:wrap; }}
  .pill {{ font-size:12px; font-weight:700; padding:3px 10px; border-radius:20px; }}
  table.targets {{ width:100%; border-collapse:collapse; font-size:14px; }}
  table.targets th {{ text-align:left; color:#9aa0ad; font-weight:600; font-size:12px;
    text-transform:uppercase; padding:6px 10px; border-bottom:1px solid #2a2a33; }}
  table.targets td {{ padding:9px 10px; border-bottom:1px solid #23242d; vertical-align:top; }}
  table.targets tr:last-child td {{ border-bottom:none; }}
  .num {{ font-family:ui-monospace,Consolas,monospace; color:#c3c7d1; text-align:right; }}
  .chip {{ font-size:11px; font-weight:700; color:#fff; padding:2px 7px; border-radius:5px;
    margin-right:4px; }}
  .verdict {{ font-weight:700; }}
  .reason {{ color:#9aa0ad; font-size:12px; }}
  .cex {{ margin-top:6px; font-size:12px; color:#b6bac4; background:#17181f;
    border:1px solid #2a2a33; border-radius:8px; padding:7px 10px;
    font-family:ui-monospace,Consolas,monospace; }}
  .safe {{ color:#30a46c; font-weight:700; margin:4px 0; font-size:15px; }}
  .note {{ color:#b6bac4; font-size:13px; margin:4px 0 0; }}
  .err {{ color:#e5484d; margin:4px 0; }}
  .muted {{ color:#9aa0ad; }}
  .danger {{ margin-top:6px; font-size:13px; color:#ffb3b5; }}
  .explain {{ margin-top:8px; border-left:3px solid #4c6ef5; background:#191b24;
    border-radius:0 8px 8px 0; padding:10px 14px; font-size:13.5px; line-height:1.6; }}
  .ex-why {{ color:#cfd3dc; }}
  .ex-fix {{ color:#b7f0cf; margin-top:7px; }}
  .explain b {{ color:#eceef2; }}
  .refnote {{ margin-top:5px; font-size:12px; color:#9aa0ad; }}
  .guide-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:14px; }}
  .guide-card {{ background:#1f2029; border:1px solid #2a2a33; border-radius:12px; padding:16px 18px; }}
  .guide-head {{ font-size:15px; font-weight:700; margin-bottom:8px; }}
  .guide-what {{ color:#b6bac4; font-size:14px; margin:0 0 8px; }}
  .guide-danger {{ color:#ffb3b5; font-size:13px; margin:0; }}
  .panels2 {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
  .vrow {{ display:flex; gap:10px; align-items:flex-start; margin-bottom:12px; font-size:14px;
    color:#c3c7d1; }}
  .vrow:last-child {{ margin-bottom:0; }}
  .vdot {{ width:12px; height:12px; border-radius:50%; margin-top:5px; flex:none; }}
  ul.cols {{ margin:0; padding-left:18px; font-size:14px; color:#c3c7d1; }}
  ul.cols li {{ margin-bottom:8px; }}
  details.source {{ margin-top:12px; border-top:1px solid #2a2a33; padding-top:10px; }}
  details.source summary {{ cursor:pointer; color:#7aa2ff; font-size:13px; font-weight:600;
    user-select:none; }}
  .srcbody {{ margin-top:10px; background:#17181f; border:1px solid #2a2a33; border-radius:8px;
    overflow:auto; font-family:ui-monospace,Consolas,monospace; font-size:12.5px; }}
  .srcline {{ display:flex; padding:0 8px; white-space:pre; }}
  .srcline.hit {{ background:#23242d; }}
  .srcline .ln {{ color:#5a5f6b; width:34px; text-align:right; margin-right:14px; flex:none;
    user-select:none; }}
  .srcline .code {{ color:#c9ccd4; }}
  @media (max-width:760px) {{ .panels, .panels2 {{ grid-template-columns:1fr; }} }}
</style></head>
<body>
<header>
  <h1>HSA — гібридний аналіз смарт-контрактів</h1>
  <p>Статичний аналіз (Slither) → спрямоване символьне виконання (Z3). Повний метод, конфігурація M1.</p>
</header>
<main>
  <div class="stats">{cards_top}</div>
  <div class="panels">
    <div class="panel"><h3>Розподіл вердиктів</h3>
      <div class="donut-wrap">{donut(totals)}<div class="legend">{legend}</div></div>
    </div>
    <div class="panel"><h3>Два етапи методу: контракти → статичні цілі → вердикти</h3>
      {funnel(len(results), total_targets, totals)}</div>
  </div>
  <div class="panel" style="margin-bottom:8px"><h3>Цілі за класом вразливості (SWC)</h3>{class_bars}</div>
  {class_guide}
  {read_guide}
  {_group_sections(results)}
</main>
</body></html>
"""


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quick", action="store_true", help="only the fast 0.8.x contracts")
    parser.add_argument("--no-open", action="store_true", help="do not open the browser")
    parser.add_argument("--out", type=Path, default=OUT, help="where to write the HTML")
    args = parser.parse_args(argv)

    cases = [case for case in DEMO_SET if case.quick or not args.quick]
    print(f"Аналізую {len(cases)} контрактів (M1)...")
    started = time.perf_counter()
    results = []
    for index, case in enumerate(cases, 1):
        print(f"  [{index}/{len(cases)}] {case.filename} ...", end=" ", flush=True)
        case_started = time.perf_counter()
        result = run_case(case)
        confirmed = result.verdict_counts.get("CONFIRMED", 0)
        print(f"{time.perf_counter() - case_started:.1f}s, {confirmed} CONFIRMED")
        results.append(result)
    elapsed = time.perf_counter() - started

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build_html(results, elapsed), encoding="utf-8")
    print(f"\nЗвіт: {args.out}  (за {elapsed:.1f}s)")
    if not args.no_open:
        webbrowser.open(args.out.resolve().as_uri())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
