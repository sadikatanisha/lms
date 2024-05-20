"use client";
import React from "react";
import { useGetAllInstructorsQuery } from "../../../redux/features/user/userApi";
import Loader from "../Loader/Loader";

const AllInstructors = () => {
  const { data, error, isLoading } = useGetAllInstructorsQuery({}); // Corrected hook name

  if (isLoading) return <Loader />;
  if (error) return <p className="text-red-500">Error loading instructors</p>;

  return (
    <div className="mt-28 flex-grow mx-4 sm:mx-8 lg:mx-16">
      <h1 className="text-3xl font-bold mb-6 text-center">All Instructors</h1>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {data.instructors.map((instructor: any) => (
          <div
            key={instructor._id}
            className="card w-full bg-base-100 shadow-xl"
          >
            <figure>
              <img
                src={
                  instructor.avatar
                    ? instructor.avatar.url
                    : "/assets/default-avatar.png"
                }
                alt={instructor.name}
                className="w-full h-48 object-cover"
              />
            </figure>
            <div className="card-body">
              <h2 className="card-title">{instructor.name}</h2>
              <p>{instructor.email}</p>
              <div className="flex justify-end mt-4">
                <button className="btn btn-primary">View Profile</button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default AllInstructors;
