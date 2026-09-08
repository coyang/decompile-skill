#include <cstdio>
#include <string>
#include <vector>

#include "cpp_shapes.h"

int main() {
  std::vector<Shape *> shapes;
  shapes.push_back(make_rect(3.0, 4.0));
  shapes.push_back(make_circle(2.0));
  printf("total=%.3f\n", total_area(shapes));
  for (size_t i = 0; i < shapes.size(); ++i) {
    printf("shape[%zu]=%s\n", i, shape_kind(shapes[i]));
  }
  printf("perim=%.3f\n", rect_perimeter(static_cast<Rectangle *>(shapes[0])));
  std::vector<int> nums;
  nums.push_back(7);
  nums.push_back(-2);
  nums.push_back(15);
  std::string s = describe("nums=", nums);
  printf("%s len=%zu\n", s.c_str(), s.size());
  for (size_t i = 0; i < shapes.size(); ++i) {
    delete shapes[i];
  }
  return 0;
}
