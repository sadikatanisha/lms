"use client";

import React, { useState } from "react";
import Heading from "../utils/Heading";
import Header from "../components/Header";
import AllInstructors from "../components/Instructors/AllInstructors";

type Props = {};

const InstructorsPage = (props: Props) => {
  const [open, setOpen] = useState(false);
  const [activeItem, setActiveItem] = useState(0);
  const [route, setRoute] = useState("Login");

  return (
    <div>
      <Heading
        title="Creati"
        description="A creative learning platform"
        keywords="art,creativity,learn"
      />
      <Header
        open={open}
        activeItem={activeItem}
        setOpen={setOpen}
        route={route}
        setRoute={setRoute}
      />
      <AllInstructors />
    </div>
  );
};

export default InstructorsPage;
