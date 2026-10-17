package df.root;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.text.style.ReplacementSpan;

/** Rounded pill drawn around the version digits in the header title.
 *  Grey ("1.07") normally; when an update is available it grows from its
 *  left edge into a lime pill reading "Update available". The growth is
 *  driven by {@link #setProgress(float)} + invalidating the title view. */
public class VersionPillSpan extends ReplacementSpan {

    private static final String UPDATE_TEXT = "Update available";

    private final float scale; // version text size relative to the title
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint bgPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private float progress;    // 0 = compact grey "1.07", 1 = lime update pill

    public VersionPillSpan(float scale) {
        this.scale = scale;
    }

    /** Animation driver: 0 = compact grey, 1 = full lime update pill. */
    public void setProgress(float p) {
        progress = Math.max(0f, Math.min(1f, p));
    }

    private static float lerp(float a, float b, float t) {
        return a + (b - a) * t;
    }

    private static int lerpColor(int a, int b, float t) {
        int ar = (a >> 16) & 0xFF, ag = (a >> 8) & 0xFF, ab = a & 0xFF;
        int br = (b >> 16) & 0xFF, bg = (b >> 8) & 0xFF, bb = b & 0xFF;
        return 0xFF000000
                | ((int) lerp(ar, br, t) << 16)
                | ((int) lerp(ag, bg, t) << 8)
                | (int) lerp(ab, bb, t);
    }

    @Override
    public int getSize(Paint paint, CharSequence text, int start, int end,
                       Paint.FontMetricsInt fm) {
        textPaint.set(paint);
        textPaint.setTextSize(paint.getTextSize() * scale);
        float padX = paint.getTextSize() * 0.22f;
        // Reserve the full width so the title layout never reflows while the
        // pill animates; the grey state simply occupies the left part.
        return (int) (textPaint.measureText(UPDATE_TEXT) + 2 * padX);
    }

    @Override
    public void draw(Canvas canvas, CharSequence text, int start, int end,
                     float x, int top, int bottom, int baseline, Paint paint) {
        textPaint.set(paint);
        textPaint.setTextSize(paint.getTextSize() * scale);

        float padX = paint.getTextSize() * 0.22f;
        float digitW = textPaint.measureText(text, start, end);
        float fullW = textPaint.measureText(UPDATE_TEXT);
        float compactW = digitW + 2 * padX;
        float fullPillW = fullW + 2 * padX;

        // The pill's visual band is the CAP HEIGHT of the pill text (digits
        // have no ascenders/descenders). Sizing it from the font's full
        // ascent is what pushed the digits toward the pill's bottom: the
        // ascent carries ~0.2em of accent headroom above the digits.
        float capSmall = textPaint.getTextSize() * 0.7f;
        float padY = capSmall * 0.45f; // big, but floating clear of cap top and baseline
        float pillH = capSmall + 2 * padY;

        // Center the pill HIGH on the headline: empirical on-device
        // calibration showed the band-middle formula rendered low next to
        // the word, so the center is raised 0.35 cap-height above the
        // cap-band middle.
        float capHeight = paint.getTextSize() * 0.7f;
        float lineCenter = baseline - capHeight * 0.85f;
        float pillTop = lineCenter - pillH / 2f;
        float pillBottom = lineCenter + pillH / 2f;

        float pillW = lerp(compactW, fullPillW, progress);
        bgPaint.setColor(lerpColor(0xFF2E2E30, 0xFFAEEA00, progress));
        canvas.drawRoundRect(
                new RectF(x, pillTop, x + pillW, pillBottom),
                pillH / 2f, pillH / 2f, bgPaint);

        // Digits dead-centered inside the pill (their band is symmetric
        // around the pill's center).
        float digitBaseline = lineCenter + capSmall / 2f;

        // "1.07" fades out while "Update available" fades in, both anchored
        // to the pill's left edge so the growth reads as expanding text.
        if (progress < 1f) {
            int fg = lerpColor(0xFFD9D9D9, 0xFF101418, progress);
            textPaint.setColor((fg & 0xFFFFFF) | ((int) (255 * (1 - progress)) << 24));
            canvas.drawText(text, start, end, x + padX, digitBaseline, textPaint);
        }
        if (progress > 0f) {
            textPaint.setColor((0xFF101418 & 0xFFFFFF) | ((int) (255 * progress) << 24));
            canvas.drawText(UPDATE_TEXT, x + padX, digitBaseline, textPaint);
        }
    }
}
