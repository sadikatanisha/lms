"use client";

import React, { FC, useState } from "react";
import Protected from "../hooks/useProtected";
import Heading from "../utils/Heading";
import Header from "../components/Header";
import Profile from "../components/Profile/Profile";
import { useSelector } from "react-redux";

type Props = {};

const ProfilePage: FC<Props> = (props: Props) => {
  const [open, setOpen] = useState(false);
  const [activeItem, setActiveItem] = useState(4);
  const [route, setRoute] = useState("Login");
  const { user } = useSelector((state: any) => state.auth);

  return (
    <div>
      <Protected>
        <div>
          <Heading
            title={`Profile`}
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
          <Profile user={user} />
        </div>
      </Protected>
    </div>
  );
};

export default ProfilePage;
