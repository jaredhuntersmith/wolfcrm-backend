import assert from "node:assert/strict";
import { executeFinanceAITool, financeAIInternals } from "../finance-ai.js";

function row(overrides = {}) {
  return { id: overrides.id || "id_1", company_id: "company_1", archived_at: null, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), ...overrides };
}

class FakePool {
  constructor() {
    this.queries = [];
  }

  async query(sql, values = []) {
    this.queries.push({ sql, values });
    if (sql.includes("INSERT INTO finance_settings")) return { rows: [row({ minimum_cash_reserve_cents: 200000, currency: "usd" })] };
    if (sql.includes("FROM finance_accounts")) return { rows: [
      row({ name: "Cash", account_type: "cash", source: "manual", current_balance_cents: 500000, currency: "usd" }),
      row({ id: "acct_2", name: "Checking", account_type: "checking", source: "plaid", current_balance_cents: 300000, available_balance_cents: 280000, currency: "usd", institution_name: "Bank", mask: "1234" })
    ] };
    if (sql.includes("FROM finance_planned_items")) return { rows: [
      row({ title: "Rent", direction: "expense", amount_cents: 100000, scheduled_date: "2026-08-20", category: "Rent", recurrence: "none" }),
      row({ id: "income_1", title: "Job", direction: "income", amount_cents: 250000, scheduled_date: "2026-08-25", category: "Income", recurrence: "none" })
    ] };
    if (sql.includes("FROM finance_debts")) return { rows: [
      row({ name: "IRS", debt_type: "federal_tax", current_balance_cents: 840000, original_balance_cents: 840000, minimum_payment_cents: 50000, planned_payment_cents: 100000, apr_basis_points: 0, next_due_date: "2026-08-15", status: "active", priority: "high" })
    ] };
    if (sql.includes("FROM finance_goals")) return { rows: [
      row({ name: "Emergency Fund", goal_type: "emergency_fund", target_amount_cents: 1000000, current_amount_cents: 250000, target_date: "2026-12-31", status: "active" })
    ] };
    if (sql.includes("FROM finance_budgets")) return { rows: [
      row({ name: "Ads", category: "Advertising", limit_cents: 100000, period: "monthly", start_date: "2026-08-01" })
    ] };
    if (sql.includes("FROM finance_transactions") && sql.includes("GROUP BY")) return { rows: [
      { label: "Advertising", transaction_count: 3, posted_cents: 120000, pending_cents: 10000, total_cents: 130000 }
    ] };
    if (sql.includes("FROM finance_transactions")) return { rows: [
      { id: "tx_1", account_id: "acct_2", account_name: "Checking", source: "plaid", status: "posted", direction: "expense", amount_cents: 30000, transaction_date: "2026-08-11", merchant_name: "Home Depot", category: "Equipment", pending: false, receipt_count: 1 }
    ] };
    if (sql.includes("FROM finance_receipts") && sql.includes("GROUP BY")) return { rows: [{ status: "unmatched", count: 2, amount_cents: 4500 }] };
    if (sql.includes("FROM finance_receipts")) return { rows: [
      { id: "receipt_1", transaction_id: null, status: "unmatched", merchant_name: "Home Depot", purchase_date: "2026-08-11", amount_cents: 30000, finance_category: "Equipment", business_use: "business", match_method: null, match_confidence: null, created_at: new Date().toISOString() }
    ] };
    if (sql.includes("INSERT INTO finance_ai_actions")) return { rows: [] };
    return { rows: [] };
  }
}

const ctx = { companyId: "company_1", userId: "user_1", conversationId: "conv_1", userMessage: "Can I afford this?" };
const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("overview tool returns deterministic safe-to-spend inputs", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "get_finance_overview", {});
  assert.equal(result.total_liquid_cash_cents, 800000);
  assert.equal(result.minimum_cash_reserve_cents, 200000);
  assert.ok(result.projection_summary);
});

test("accounts tool returns safe account details only", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "get_accounts", {});
  assert.equal(result.length, 2);
  assert.equal(Object.prototype.hasOwnProperty.call(result[0], "access_token"), false);
});

test("transaction filters are company scoped", async () => {
  const pool = new FakePool();
  await executeFinanceAITool(pool, ctx, "get_transactions", { period: "custom", start_date: null, end_date: null, direction: "expense", account_id: null, category: null, merchant_query: "home", status: "posted", limit: 10 });
  assert.equal(pool.queries.some((query) => query.values[0] === "company_1"), true);
});

test("spending summary aggregates backend-side", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "get_spending_summary", { period: null, start_date: null, end_date: null, group_by: "category", account_id: null, category: null, merchant_query: null, limit: 10 });
  assert.equal(result.groups[0].total_cents, 130000);
  assert.equal(result.posted_spending_cents, 120000);
  assert.equal(result.pending_spending_cents, 10000);
});

test("spending summary normalizes safe enum synonyms", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "get_spending_summary", {
    period: "previous_month",
    start_date: null,
    end_date: null,
    group_by: "categories",
    direction: "expenses",
    account_id: null,
    category: null,
    merchant_query: null,
    limit: 10
  });
  assert.equal(result.period.key, "last_month");
  assert.equal(result.group_by, "category");
  assert.equal(result.direction, "expense");
});

test("spending summary normalizes merchant plural", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "get_spending_summary", {
    period: "last_month",
    start_date: null,
    end_date: null,
    group_by: "merchants",
    direction: "spending",
    account_id: null,
    category: null,
    merchant_query: null,
    limit: 10
  });
  assert.equal(result.group_by, "merchant");
  assert.equal(result.direction, "expense");
});

test("spending summary rejects unknown enum values", async () => {
  await assert.rejects(
    () => executeFinanceAITool(new FakePool(), ctx, "get_spending_summary", {
      period: "last_month",
      start_date: null,
      end_date: null,
      group_by: "merchant_and_category",
      direction: "expense",
      account_id: null,
      category: null,
      merchant_query: null,
      limit: 10
    }),
    (error) => error.code === "finance_ai_invalid_tool_arguments"
  );
});

test("spending summary treats empty data as a zero result", async () => {
  const pool = new FakePool();
  pool.query = async (sql, values = []) => {
    pool.queries.push({ sql, values });
    if (sql.includes("FROM finance_transactions") && sql.includes("GROUP BY")) return { rows: [] };
    return FakePool.prototype.query.call(pool, sql, values);
  };
  const result = await executeFinanceAITool(pool, ctx, "get_spending_summary", { period: "last_month", start_date: null, end_date: null, group_by: "category", account_id: null, category: null, merchant_query: null, limit: 10 });
  assert.equal(result.total_spending_cents, 0);
  assert.equal(result.transaction_count, 0);
  assert.deepEqual(result.groups, []);
});

test("last month resolves to previous calendar month", () => {
  const result = financeAIInternals.resolveDateRange("last_month", null, null, "2026-08-11");
  assert.deepEqual(result, { key: "last_month", start_date: "2026-07-01", end_date: "2026-07-31" });
});

test("cash-flow projection tool returns projection", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "get_cash_flow_projection", { horizon_days: 30 });
  assert.equal(result.starting_balance_cents, 800000);
});

test("budget tool returns budget summary", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "get_budget_status", { period: "monthly", category: null });
  assert.ok(Array.isArray(result.budgets));
});

test("debts tool returns debt summary", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "get_debts", {});
  assert.equal(result.summary.tax_debt_cents, 840000);
});

test("debt payoff supports hypothetical payment", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "get_debt_payoff", { debt_id: "id_1", planned_payment_cents: 150000 });
  assert.equal(result.debt.name, "IRS");
  assert.ok(result.payoff);
});

test("goals tool returns goal summary", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "get_goals", {});
  assert.equal(result.goals[0].name, "Emergency Fund");
});

test("receipts tool excludes image URLs and OCR", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "get_receipts", { merchant: "home", status: "all", start_date: null, end_date: null, amount_cents: null, category: null, limit: 10 });
  assert.equal(Object.prototype.hasOwnProperty.call(result[0], "download_url"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(result[0], "ocr_text"), false);
});

test("affordability preview validates amount", async () => {
  await assert.rejects(() => executeFinanceAITool(new FakePool(), ctx, "preview_purchase_impact", { amount_cents: 0, purchase_date: null, category: null, description: null, projection_horizon_days: 30 }));
});

test("affordability preview is deterministic", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "preview_purchase_impact", { amount_cents: 300000, purchase_date: null, category: "Equipment", description: "Pressure washer", projection_horizon_days: 30 });
  assert.equal(result.current_liquid_cash_cents, 800000);
  assert.equal(result.scenario_ending_balance_cents, result.baseline_ending_balance_cents - 300000);
});

test("income downside scenario returns safe-to-spend delta", async () => {
  const result = await executeFinanceAITool(new FakePool(), ctx, "preview_income_change", { percent_change: -30, start_date: null, end_date: null, projection_horizon_days: 30 });
  assert.equal(typeof result.safe_to_spend_change_cents, "number");
});

test("debt payment preview rejects invalid company debt", async () => {
  const pool = new FakePool();
  pool.query = async (sql, values) => {
    pool.queries.push({ sql, values });
    if (sql.includes("FROM finance_debts")) return { rows: [] };
    return { rows: [] };
  };
  await assert.rejects(() => executeFinanceAITool(pool, ctx, "preview_debt_payment", { debt_id: "other_company", planned_payment_cents: 100000, projection_horizon_days: 30 }));
});

test("write tools require explicit intent", async () => {
  await assert.rejects(() => executeFinanceAITool(new FakePool(), ctx, "create_budget", { name: "Ads", category: "Advertising", limit_cents: 100000, period: "monthly" }));
});

test("explicit write creates audit record", async () => {
  const pool = new FakePool();
  await executeFinanceAITool(pool, { ...ctx, userMessage: "Create an ads budget" }, "create_budget", { name: "Ads", category: "Advertising", limit_cents: 100000, period: "monthly" });
  assert.equal(pool.queries.some((query) => query.sql.includes("INSERT INTO finance_ai_actions")), true);
});

test("tool loop completes spending-summary question with non-empty text", async () => {
  const calls = [];
  const client = {
    responses: {
      create: async ({ input }) => {
        calls.push(input.map((item) => ({ type: item.type, call_id: item.call_id })));
        if (calls.length === 1) {
          return {
            output_text: "",
            output: [{
              type: "function_call",
              name: "get_spending_summary",
              call_id: "call_spend",
              arguments: JSON.stringify({ period: "last_month", start_date: null, end_date: null, group_by: "category", account_id: null, category: null, merchant_query: null, limit: 10 })
            }]
          };
        }
        return {
          output_text: "I don't have any posted expense transactions for last month.",
          output: []
        };
      }
    }
  };
  const result = await financeAIInternals.runResponsesToolLoop({
    pool: new FakePool(),
    client,
    model: "test-model",
    input: [{ role: "user", content: "Where did my money go last month?" }],
    ctx
  });
  assert.match(result.text, /last month/);
});

test("concurrent tool loop preserves function call output IDs", async () => {
  const createdInputs = [];
  const client = {
    responses: {
      create: async ({ input }) => {
        createdInputs.push(input);
        if (createdInputs.length === 1) {
          return {
            output_text: "",
            output: [
              { type: "function_call", name: "get_finance_overview", call_id: "A", arguments: "{}" },
              { type: "function_call", name: "get_debts", call_id: "B", arguments: "{}" },
              { type: "function_call", name: "get_budget_status", call_id: "C", arguments: JSON.stringify({ period: "monthly", category: null }) }
            ]
          };
        }
        return { output_text: "Here is the summary.", output: [] };
      }
    }
  };
  const delays = { get_finance_overview: 30, get_debts: 20, get_budget_status: 10 };
  await financeAIInternals.runResponsesToolLoop({
    pool: new FakePool(),
    client,
    model: "test-model",
    input: [{ role: "user", content: "Can I spend and still handle debt?" }],
    ctx,
    executeTool: async (_pool, _ctx, name) => {
      await new Promise((resolve) => setTimeout(resolve, delays[name] || 1));
      return { name };
    }
  });
  const outputs = createdInputs[1].filter((item) => item.type === "function_call_output");
  assert.equal(outputs.length, 3);
  assert.equal(JSON.parse(outputs.find((item) => item.call_id === "A").output).data.name, "get_finance_overview");
  assert.equal(JSON.parse(outputs.find((item) => item.call_id === "B").output).data.name, "get_debts");
  assert.equal(JSON.parse(outputs.find((item) => item.call_id === "C").output).data.name, "get_budget_status");
});

test("tool loop rejects genuinely empty final output", async () => {
  const client = { responses: { create: async () => ({ output_text: "", output: [] }) } };
  await assert.rejects(
    () => financeAIInternals.runResponsesToolLoop({
      pool: new FakePool(),
      client,
      model: "test-model",
      input: [{ role: "user", content: "hey" }],
      ctx
    }),
    /usable answer/
  );
});

test("empty final response after successful tools gets one recovery pass", async () => {
  let createCount = 0;
  const requests = [];
  const client = {
    responses: {
      create: async (request) => {
        requests.push(request);
        createCount += 1;
        if (createCount === 1) {
          return {
            output_text: "",
            output: [
              {
                type: "function_call",
                name: "get_spending_summary",
                call_id: "category_call",
                arguments: JSON.stringify({ period: "last_month", start_date: null, end_date: null, group_by: "category", account_id: null, category: null, merchant_query: null, limit: 10 })
              },
              {
                type: "function_call",
                name: "get_spending_summary",
                call_id: "merchant_call",
                arguments: JSON.stringify({ period: "last_month", start_date: null, end_date: null, group_by: "merchant", account_id: null, category: null, merchant_query: null, limit: 20 })
              }
            ]
          };
        }
        if (createCount === 2) return { output_text: "", output: [] };
        return { output_text: "Your biggest discretionary-looking expenses were dining and shopping.", output: [] };
      }
    }
  };
  const result = await financeAIInternals.runResponsesToolLoop({
    pool: new FakePool(),
    client,
    model: "test-model",
    input: [{ role: "user", content: "What were my biggest unnecessary expenses?" }],
    ctx
  });
  assert.equal(createCount, 3);
  assert.equal(Object.prototype.hasOwnProperty.call(requests[2], "tools"), false);
  assert.match(result.text, /discretionary-looking/);
});

test("real discretionary-spend failure shape forces final synthesis with tools disabled", async () => {
  let createCount = 0;
  const requests = [];
  const client = {
    responses: {
      create: async (request) => {
        requests.push(request);
        createCount += 1;
        if (createCount === 1) {
          return {
            output_text: "",
            output: [{
              type: "function_call",
              name: "get_spending_summary",
              call_id: "first_category",
              arguments: JSON.stringify({ period: "last_month", start_date: null, end_date: null, group_by: "category", direction: "expense", account_id: null, category: null, merchant_query: null, limit: 10 })
            }]
          };
        }
        if (createCount === 2) {
          return {
            output_text: "",
            output: [
              {
                type: "function_call",
                name: "get_spending_summary",
                call_id: "merchant_valid",
                arguments: JSON.stringify({ period: "last_month", start_date: null, end_date: null, group_by: "merchant", direction: "expense", account_id: null, category: null, merchant_query: null, limit: 20 })
              },
              {
                type: "function_call",
                name: "get_spending_summary",
                call_id: "invalid_combo",
                arguments: JSON.stringify({ period: "last_month", start_date: null, end_date: null, group_by: "merchant_and_category", direction: "expense", account_id: null, category: null, merchant_query: null, limit: 20 })
              }
            ]
          };
        }
        if (createCount === 3) {
          return {
            output_text: "",
            output: [{
              type: "function_call",
              name: "get_spending_summary",
              call_id: "third_category",
              arguments: JSON.stringify({ period: "last_month", start_date: null, end_date: null, group_by: "categories", direction: "expenses", account_id: null, category: null, merchant_query: null, limit: 10 })
            }]
          };
        }
        return { output_text: "Your largest discretionary-looking expenses last month were dining and shopping.", output: [] };
      }
    }
  };
  const result = await financeAIInternals.runResponsesToolLoop({
    pool: new FakePool(),
    client,
    model: "test-model",
    input: [{ role: "user", content: "What kind of unnecessary expenses did I make last month?" }],
    ctx
  });
  assert.equal(createCount, 4);
  assert.equal(Object.prototype.hasOwnProperty.call(requests[3], "tools"), false);
  assert.match(result.text, /discretionary-looking/);
});

test("empty final recovery fails with finance_ai_empty_response when still empty", async () => {
  let createCount = 0;
  const client = {
    responses: {
      create: async () => {
        createCount += 1;
        if (createCount === 1) {
          return {
            output_text: "",
            output: [{
              type: "function_call",
              name: "get_spending_summary",
              call_id: "category_call",
              arguments: JSON.stringify({ period: "last_month", start_date: null, end_date: null, group_by: "category", account_id: null, category: null, merchant_query: null, limit: 10 })
            }]
          };
        }
        return { output_text: "", output: [] };
      }
    }
  };
  await assert.rejects(
    () => financeAIInternals.runResponsesToolLoop({
      pool: new FakePool(),
      client,
      model: "test-model",
      input: [{ role: "user", content: "What were my biggest unnecessary expenses?" }],
      ctx
    }),
    (error) => error.code === "finance_ai_empty_response"
  );
  assert.equal(createCount, 3);
});

test("duplicate identical tool calls execute once and return both call IDs", async () => {
  const createdInputs = [];
  const toolArgs = { period: "last_month", start_date: null, end_date: null, group_by: "category", account_id: null, category: null, merchant_query: null, limit: 10 };
  const client = {
    responses: {
      create: async ({ input }) => {
        createdInputs.push(input);
        if (createdInputs.length === 1) {
          return {
            output_text: "",
            output: [
              { type: "function_call", name: "get_spending_summary", call_id: "A", arguments: JSON.stringify(toolArgs) },
              { type: "function_call", name: "get_spending_summary", call_id: "B", arguments: JSON.stringify(toolArgs) }
            ]
          };
        }
        return { output_text: "Here are the categories.", output: [] };
      }
    }
  };
  let executions = 0;
  await financeAIInternals.runResponsesToolLoop({
    pool: new FakePool(),
    client,
    model: "test-model",
    input: [{ role: "user", content: "Where did my money go last month?" }],
    ctx,
    executeTool: async () => {
      executions += 1;
      return { groups: [{ label: "Dining", total_cents: 1000 }] };
    }
  });
  const outputs = createdInputs[1].filter((item) => item.type === "function_call_output");
  assert.equal(executions, 1);
  assert.equal(outputs.length, 2);
  assert.equal(Boolean(outputs.find((item) => item.call_id === "A")), true);
  assert.equal(Boolean(outputs.find((item) => item.call_id === "B")), true);
});

test("visible assistant text extraction handles common response shapes", () => {
  assert.equal(financeAIInternals.extractVisibleAssistantText({ output_text: "hello", output: [] }), "hello");
  assert.equal(financeAIInternals.extractVisibleAssistantText({ output_text: "", output: [{ type: "function_call", call_id: "A" }] }), "");
  assert.equal(financeAIInternals.extractVisibleAssistantText({ output: [{ type: "message", content: [{ type: "output_text", text: "block one" }, { type: "output_text", text: " block two" }] }] }), "block one block two");
  assert.equal(financeAIInternals.extractVisibleAssistantText({ output: [] }), "");
});

test("tool output serializer handles BigInt and undefined", () => {
  const output = JSON.parse(financeAIInternals.safeToolOutputString({ amount_cents: 123n, missing: undefined }));
  assert.equal(output.amount_cents, 123);
  assert.equal(output.missing, null);
});

let passed = 0;
for (const item of tests) {
  try {
    await item.fn();
    passed += 1;
    console.log(`PASS ${item.name}`);
  } catch (error) {
    console.error(`FAIL ${item.name}`);
    console.error(error);
    process.exitCode = 1;
    break;
  }
}

if (!process.exitCode) console.log(`PASS finance AI tools (${passed}/${tests.length})`);
