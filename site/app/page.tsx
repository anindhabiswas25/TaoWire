import Header from "@/components/Header";
import Hero from "@/components/Hero";
import Modules from "@/components/Modules";
import Pipeline from "@/components/Pipeline";
import { AgentsAndMigration, Cta, Footer, Install, Quickstart, Tested, Ticker, Why } from "@/components/Sections";
import { CodeTabs, Commands } from "@/components/Terminal";

export default function Page() {
  return (
    <>
      <div className="guides" aria-hidden="true">
        <div className="wrap">
          <i style={{ left: "25%" }} /><i style={{ left: "50%" }} /><i style={{ left: "75%" }} />
        </div>
      </div>
      <Header />
      <main>
        <div className="wrap">
          <Hero />
          <Ticker />
          <Why />
          <Pipeline />
          <Modules />
          <CodeTabs />
          <Commands />
          <Install />
          <Quickstart />
          <AgentsAndMigration />
          <Tested />
          <Cta />
        </div>
      </main>
      <Footer />
    </>
  );
}
