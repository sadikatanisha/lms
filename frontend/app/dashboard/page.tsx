"use client";
import React from "react";
import Heading from "../utils/Heading";
import DashboardSidebar from "../components/Dashboard/DashboardSidebar";
import Protected from "../hooks/useProtected";

type Props = {};

const page = (props: Props) => {
  return (
    <div>
      <Protected>
        <Heading
          title={"Creati - Dashboard"}
          description="dashboard"
          keywords="dashboard"
        />

        <div className="flex h-screen ">
          <div className="flex h-screen flex-row justify-start">
            <DashboardSidebar />
          </div>
        </div>
      </Protected>
    </div>
  );
};

export default page;
