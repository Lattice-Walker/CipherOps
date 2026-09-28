%%manim -qm NetworkTopologies

SAGE = "#87A878"
LAVENDER = "#B8A9C9"

class NetworkTopologies(Scene):
    def construct(self):
        self.camera.background_color = BACKGROUND

        topologies = [
            self.bus_topology,
            self.star_topology,
            self.ring_topology,
            self.mesh_topology,
            self.tree_topology,
        ]
        names = ["Bus", "Star", "Ring", "Mesh", "Tree"]

        # 10 seconds total across 5 topologies
        # FadeIn 0.5s + FadeOut 0.5s = 1s overhead per slide
        # hold = (10 - 5 * 1) / 5 = 1s per slide
        fade_time = 0.5
        hold_time = (10 - len(topologies) * fade_time * 2) / len(topologies)

        for build_fn, name in zip(topologies, names):
            group = build_fn()
            label = Text(
                name,
                font_size=48,
                color=SAGE,
                weight=BOLD,
                stroke_width=3,
                stroke_color=SAGE,
            ).next_to(group, DOWN, buff=0.4)
            full = VGroup(group, label).move_to(ORIGIN)

            self.play(FadeIn(full), run_time=fade_time)
            self.wait(hold_time)
            self.play(FadeOut(full), run_time=fade_time)


    def make_node(self, position):
        return Dot(point=position, radius=0.198, color=SAGE).set_stroke(SAGE, width=0)

    def make_edge(self, a, b):
        return Line(a.get_center(), b.get_center(), color=LAVENDER, stroke_width=6.5)

    def bus_topology(self):
        bus = Line(LEFT * 3, RIGHT * 3, color=LAVENDER, stroke_width=7.5)
        positions = [LEFT * 2, LEFT * 1, ORIGIN, RIGHT * 1, RIGHT * 2]
        nodes = [self.make_node(p + UP * 1.2) for p in positions]
        drops = [
            Line(p, n.get_center(), color=LAVENDER, stroke_width=6.5)
            for p, n in zip(positions, nodes)
        ]
        return VGroup(bus, *drops, *nodes)


    def star_topology(self):
        center = self.make_node(ORIGIN)
        angles = [i * TAU / 6 for i in range(6)]
        leaves = [
            self.make_node(1.8 * np.array([np.cos(a), np.sin(a), 0]))
            for a in angles
        ]
        edges = [self.make_edge(center, leaf) for leaf in leaves]
        return VGroup(*edges, center, *leaves)

    def ring_topology(self):
        n = 6
        angles = [i * TAU / n for i in range(n)]
        nodes = [
            self.make_node(1.8 * np.array([np.cos(a), np.sin(a), 0]))
            for a in angles
        ]
        edges = [self.make_edge(nodes[i], nodes[(i + 1) % n]) for i in range(n)]
        return VGroup(*edges, *nodes)

    def mesh_topology(self):
        positions = [
            UP * 1.2,
            UP * 1.2 + RIGHT * 1.8,
            DOWN * 0.6,
            DOWN * 0.6 + RIGHT * 1.8,
            DOWN * 0.6 + RIGHT * 0.9 + UP * 0.9,
        ]
        nodes = [self.make_node(p - RIGHT * 0.9) for p in positions]
        edges = []
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                edges.append(self.make_edge(nodes[i], nodes[j]))
        return VGroup(*edges, *nodes)

    def tree_topology(self):
        root = self.make_node(UP * 2)
        l1 = [
            self.make_node(UP * 0.6 + LEFT * 1.6),
            self.make_node(UP * 0.6 + RIGHT * 1.6),
        ]
        l2 = [
            self.make_node(DOWN * 0.8 + LEFT * 2.4),
            self.make_node(DOWN * 0.8 + LEFT * 0.8),
            self.make_node(DOWN * 0.8 + RIGHT * 0.8),
            self.make_node(DOWN * 0.8 + RIGHT * 2.4),
        ]
        edges = (
            [self.make_edge(root, c) for c in l1]
            + [self.make_edge(l1[0], l2[0]), self.make_edge(l1[0], l2[1])]
            + [self.make_edge(l1[1], l2[2]), self.make_edge(l1[1], l2[3])]
        )
        return VGroup(*edges, root, *l1, *l2)
