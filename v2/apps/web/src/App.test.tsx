import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App";

function renderAt(route: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[route]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

afterEach(cleanup);

describe("operator console", () => {
  it("renders the environment creation flow with hierarchy and progress", () => {
    renderAt("/environments/new");
    expect(screen.getByRole("heading", { name: "Create environment" })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Creation progress" })).toHaveTextContent("Basics");
    expect(screen.getByRole("textbox", { name: /Name/i })).toBeInTheDocument();
  });

  it("keeps destructive environment actions in their own settings area", async () => {
    renderAt("/environments/env-aurora/settings");
    expect(await screen.findByRole("heading", { name: "Environment settings" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Review destruction/i })).toHaveAttribute("href", "/environments/00000000-0000-4000-8000-000000000001/destroy");
  });

  it("renders product settings with a system theme default", () => {
    renderAt("/settings");
    expect(screen.getByRole("heading", { name: "Settings" })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "System" })).toBeChecked();
  });

  it("advances through the workload manifest builder only with valid package metadata", () => {
    renderAt("/workloads/import");
    const continueButton = screen.getByRole("button", { name: /Continue/i });
    expect(continueButton).toBeDisabled();
    fireEvent.change(screen.getByRole("textbox", { name: "Package name" }), { target: { value: "HTTP redirector" } });
    expect(continueButton).toBeEnabled();
    fireEvent.click(continueButton);
    expect(screen.getByRole("heading", { name: "Compose definition" })).toBeInTheDocument();
  });

  it("opens a real AWS connection validation and save flow", () => {
    renderAt("/connections");
    fireEvent.click(screen.getByRole("button", { name: "Add connection" }));
    expect(screen.getByRole("heading", { name: "Add AWS connection" })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Connection name" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Validate credentials" })).toBeInTheDocument();
  });
});
