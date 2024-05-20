import { apiSlice } from "../api/apiSlice";

export const courseApi = apiSlice.injectEndpoints({
  endpoints: (builder) => ({
    createCourse: builder.mutation({
      query: (data) => ({
        url: "create-course",
        method: "POST",
        body: data,
        credentials: "include" as const,
      }),
    }),
    getUserCourses: builder.query({
      query: (data) => ({
        url: "my-courses",
        method: "GET",
        credentials: "include" as const,
      }),
    }),
    getAllCourses: builder.query({
      query: (data) => ({
        url: "get-courses",
        method: "GET",
        credentials: "include" as const,
      }),
    }),
    getApprovedCourses: builder.query({
      query: (data) => ({
        url: "get-approved-courses",
        method: "GET",
        credentials: "include" as const,
      }),
    }),
    updateCourseStatus: builder.mutation({
      query: ({ courseId, status, adminFeedback }) => ({
        url: `update-course-status/${courseId}`,
        method: "PUT",
        body: { status, adminFeedback },
        credentials: "include" as const,
      }),
    }),
  }),
});

export const {
  useCreateCourseMutation,
  useGetUserCoursesQuery,
  useGetAllCoursesQuery,
  useUpdateCourseStatusMutation,
  useGetApprovedCoursesQuery,
} = courseApi;
