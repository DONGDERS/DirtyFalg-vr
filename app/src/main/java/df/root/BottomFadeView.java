package df.root;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.view.View;

/**
 * OneUI-style bottom fade. Draws a LinearGradient with explicit positions
 * so the curve can be aggressive (steep late falloff) while still starting
 * at fully transparent - no visible seam at the top edge.
 */
public class BottomFadeView extends View {

    private final Paint paint = new Paint();

    // Fade curve: nothing at all for the first half, then a long easy slope -
    // 25% at half way, 60% at three quarters, solid only in the last tenth. The
    // old curve was already 40% grey at a third of the way down and solid at 82%,
    // which swallowed half the readable log and left the bottom of the box as
    // dead black space.
    private static final int[] COLORS = {
            0x00000000,
            0x40000000,
            0x99000000,
            0xFF000000,
            0xFF000000
    };
    private static final float[] POSITIONS = {0f, 0.50f, 0.72f, 0.93f, 1f};

    public BottomFadeView(Context context) {
        super(context);
    }

    public BottomFadeView(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public BottomFadeView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
    }

    @Override
    protected void onSizeChanged(int w, int h, int oldW, int oldH) {
        super.onSizeChanged(w, h, oldW, oldH);
        paint.setShader(new LinearGradient(0, 0, 0, h, COLORS, POSITIONS, Shader.TileMode.CLAMP));
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        canvas.drawRect(0, 0, getWidth(), getHeight(), paint);
    }
}
